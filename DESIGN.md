# ApiSessionBundle - Design

## Problem statement

Symfony's stateful firewalls assume the session id travels in a cookie.
Browser-less API clients (mobile apps, SPAs avoiding cookies,
server-to-server callers) commonly want `Authorization: Bearer <token>`
semantics instead - but stateless token schemes (JWT etc.) give up the
things server-side sessions provide for free: instant revocation,
server-side state (including Symfony's impersonation state), idle
expiry, and no claims-refresh problem.

This bundle bridges the two: a **stateful** firewall whose session id is
carried in the `Authorization` header. It also replaces Symfony's
"magic parameter on any URL" switch-user mechanism with explicit,
app-registered API endpoints, and it coexists with other authentication
that uses the `Authorization` header (e.g. an OIDC access token used to
log in and establish the session in the first place).

## Requirements

### Functional

- F1. A firewall can be configured so the session id is resolved from
  `Authorization: Bearer <token>`; the cookie path is fully disabled for
  that firewall: no `Set-Cookie` is ever emitted and session cookies
  sent by clients are ignored.
- F2. On successful login (however the app authenticates - `json_login`,
  WebAuthn, OIDC, custom authenticator), a session is created and the
  bearer token for it is made available to the application and the
  client (response header and/or body).
- F3. **Pre-authentication sessions**: a session may legitimately exist
  *before* any authentication - a WebAuthn challenge stored between the
  options and verify steps of a passkey ceremony, OIDC `state`, a
  CSRF-protected login form. Such anonymous sessions get a bearer token
  too (whenever a bridged-firewall request starts a session without
  presenting a valid token), and login rotates it.
- F4. Switch-user works only via dedicated endpoints the app opts into
  (enter + exit impersonation); the generic `_switch_user` request
  parameter must not work anywhere.
- F5. Bearer values that are *not* session tokens (e.g. OIDC JWTs) pass
  through untouched so other authenticators on the same firewall can
  consume them.
- F6. Logout invalidates the server-side session; every outstanding
  token for it becomes unusable immediately.
- F7. Optionally, tokens carry an absolute lifetime, with a refresh
  endpoint to mint replacements.

### Non-functional

- N1. No custom session storage requirement - works with whatever
  session handler the app configured (files, Redis, PDO…).
- N2. Standard Symfony security integration: `security.yaml`
  configuration, normal `TokenStorage`/`Security` behaviour, events and
  voters unaffected.
- N3. Safe against session fixation/adoption (a client must not be able
  to choose its own session id by presenting an arbitrary token).
- N4. Works alongside a classic cookie-based firewall in the same app
  (e.g. `main` for a web UI, `api` for this bundle). Mixed mode - one
  firewall accepting cookie *and* bearer sessions simultaneously - is
  out of scope.

## Architecture

### 1. Bearer → session bridge

A `kernel.request` listener registered after the framework has attached
the session factory (priority 128) and before the firewall (priority 8):

1. Extract the bearer value and decode it through the token strategy
   (§3). Not one of ours → do nothing; the header stays available for
   other authenticators (F5).
2. If the token carries an expiry that has passed, reject it *before
   the session is ever touched* and route it into the stale-token
   signalling (§2); the request proceeds as tokenless.
3. Otherwise inject the session id with `setId()`, and mirror it into
   the request's cookie bag: the security ContextListener only restores
   a token when `Request::hasPreviousSession()` is true, which checks
   for the session cookie. The explicit `setId()` is what the session
   actually uses.
4. With no (valid) token, force a fresh random id so a session cookie
   is never honoured on a bridged firewall; under native sessions with
   `use_strict_mode` the unknown id itself is replaced at start.

A `kernel.response` listener suppresses every session cookie the
framework (or logout's cookie clearing) attached, and **advertises** the
current token in a configurable response header whenever the session is
started and its id no longer matches the presented one - one rule that
covers anonymous-session creation (F3), login migration (rotation, N3),
and sessions minted by other authenticators on the firewall.

Because tokens are computable from whatever session id the session layer
chose (§3), PHP/Symfony keep full ownership of ids: Symfony's stock
session-fixation migration at login just works.

### 2. Stale-token signalling

When a presented token verifies as ours but is no longer usable - its
embedded expiry passed, or its session is gone (idle-expired, logged
out, invalidated) - three signals fire:

- a request attribute (`StaleTokenDetector::STALE_ATTRIBUTE`), computed
  before the security entry point runs, so apps can shape their own 401
  ("session expired, log in again" vs "no credentials");
- `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750) appended
  to 401 responses - on by default, `stale_token.www_authenticate:
  false` to disable; appended, never replaced, so other challenges
  (e.g. a Basic one from an entry point) survive;
- a `StaleSessionTokenEvent` (once per request) for telemetry or custom
  handling.

Dead-session detection uses a **liveness marker** stamped into every
session the bridge saves: id comparison cannot distinguish "dead
session" from a legitimate login migration, and lenient session
storages silently adopt unknown ids - a marker-less session reached
through a presented token was never saved by us, hence stale. The
verdict is only computed on failure paths (401s and auth exceptions),
which keeps logout responses and login migrations out of scope, and a
live-but-anonymous token (e.g. mid passkey ceremony) is correctly *not*
flagged - its session has the marker. A stale verdict also suppresses
the marker stamp when a lenient storage adopted the dead id, so such an
id can never be resurrected by repeated presentation.

### 3. Token strategy and format

The strategy interface encodes a claims **pair** - session id plus
optional absolute expiry - so expiry lives in the signed token, not in
mutable session state (any app code touching the session could
otherwise corrupt bundle expiry bookkeeping into a security hole):

```php
interface TokenStrategyInterface
{
    public function mint(string $sessionId, ?int $expiresAt = null): string;
    public function extract(string $bearerValue): ?SessionToken; // null = not ours
}
// SessionToken = { string $sessionId, ?int $expiresAt }
```

`extract()` returning null **is** the discriminator (F5): OIDC JWTs,
garbage, and foreign tokens fall through untouched. Expiry is *enforced
by the bridge* from the decoded claims.

**Security contract for custom strategies** (documented on the
interface): every claim - id and expiry - must be integrity-protected;
an encoding that lets the client alter the expiry is exploitable by
construction, and that responsibility sits with the implementation.
Strategies must be able to mint for any session id the session layer
chooses - a *non-invertible* mapping (session id derived by hashing the
token) is unsupported, because it would force the bundle to control
session-id selection everywhere (prospective ids on tokenless requests,
custom login migration).

Default implementation, keyed by a domain-separated derivation of
`kernel.secret` (never the raw secret), prefix configurable
(`token.prefix`, default `sess_`, non-empty and dot-free):

```
without lifetime: <prefix><sid>.<base64url hmac-sha256(sid)>
with lifetime:    <prefix><sid>.<unix-expiry>.<base64url hmac-sha256(sid.expiry)>
```

Threat model served by the signature:

- *Store-key leakage* (Redis SCAN/monitoring, backups, file listings,
  logs of the session store) - a leaked session-store key is *not* a
  usable credential; building the Authorization header requires the app
  secret.
- *Session adoption* (client-chosen storage keys) - already blocked by
  `session.use_strict_mode`; the MAC additionally makes a forged token
  for a chosen sid impossible (N3).
- *Classic fixation* - killed by token rotation at login, which falls
  out of Symfony's ordinary id migration.

The MAC covers the expiry, so clients may read it (useful for proactive
refresh) but cannot alter or strip it; sids cannot contain the claim
separator, so the MAC payload is boundary-unambiguous. With a non-empty
prefix the three-segment form cannot be confused with a JWT. Trade-off:
rotating `kernel.secret` invalidates all outstanding tokens.
Alternative strategies remain possible - e.g. authenticated encryption
of the claims, which additionally hides the session id from the client.

### 4. Token issuance

`SessionTokenIssuer` is the single place a token comes into existence:
it applies the configured lifetime and dispatches
`SessionTokenMintedEvent` (§8), so no mint can bypass either. The
bundle mints in three places - the response-header advertisement (§1),
the opt-in login controller, and the refresh endpoint - and apps can
inject the issuer to hand out tokens from their own endpoints (e.g. in
the JSON body of a challenge response).

Client contract: any response carrying the token response-header
announces the *current* token; the client stores it and uses it from
then on. In practice the token changes at anonymous-session creation
and at login; with `token.lifetime` enabled, a refresh additionally
mints a new token (same session) whose predecessor stays valid until
its own embedded expiry.

### 5. Absolute lifetime and refresh

By default a token lives as long as its session (sliding idle expiry -
a regularly-used token stays valid, an abandoned one dies with the
session's GC). `token.lifetime` adds an absolute bound, embedded and
signed in each minted token:

- The bridge rejects an expired token at decode time, before the
  session is consulted, into the stale-token signalling (§2).
- *Refresh* (`RefreshTokenController`, app-mounted) mints an
  **additional** token for the *same* session id with a fresh expiry -
  no session migration, no server-side state, and concurrent refreshes
  from racing client threads are harmless.
- **Refresh does not revoke the previous token** - inherent to
  stateless expiry (no server-side token list to strike from).
  Revocation is what logout/session invalidation is for: the sid dies,
  killing *every* outstanding token of the session at once (F6).
  Sessions are also effectively immortal under active refresh; there is
  no built-in cap on total session age. Both properties can be
  tightened app-side (§8).
- Enabling `token.lifetime` only affects newly minted tokens;
  outstanding non-expiring tokens cannot be retrofitted.

Alternatives considered and rejected: rotation-on-use (every response
carries a fresh token) has bad ergonomics for clients with concurrent
in-flight requests - two responses can disagree about the "current"
token; session-stamped expiry (mint time kept in session data) turns
any session-manipulating app code into a potential security hole.

### 6. Switch-user endpoints

Symfony's `switch_user` firewall option stays disabled - its listener
honours the magic parameter on every request. The bundle instead ships
enter/exit impersonation controllers and registers **no routes**: the
app declares routes pointing at them, so nothing impersonation-related
exists unless the app opts in, and the app controls paths and methods.

Semantics mirror the built-in feature: the impersonation token wraps the
original token and carries the target's roles, so `IS_IMPERSONATOR` and
exit-permission voters behave as usual; the session token is *not*
rotated by enter/exit.

Mirroring the built-in feature includes its role set, which changed
under us. Up to security-http 6.4, `SwitchUserListener` appended
`ROLE_PREVIOUS_ADMIN` to the token and
`ContextListener::hasUserChanged()` added that role to the set it
expected the token to carry; 7.0 removed both halves together. The
convention is therefore all-or-nothing per version: a token carrying the
role on 7.0+, or omitting it on 6.4, disagrees with the roles the
provider reloads, which reads as "the user changed" and deauthenticates
the session on the *next* request - enter answers 200 and everything
after it 401s. The enter controller appends the role only below 7.0.

Which side of 7.0 we are on is guessed from `Kernel::VERSION_ID`, i.e.
http-kernel's version standing in for security-http's; their constraints
permit different majors (security-http 6.4 accepts http-kernel `^7.0`),
and that pairing is exactly where the guess is wrong. Rather than take a
`composer-runtime-api` dependency to read security-http's own version,
the guess is the *default* of a three-state option,
`switch_user.grant_previous_admin_role: auto|true|false`, so any install
the guess fails can state the answer. `auto` normalises to a null
container parameter and is resolved per request, not at compile time - a
container built before a Symfony major upgrade must not bake in the old
answer.

This is invisible to any test whose user implements `EquatableInterface`
(`InMemoryUser` does): `hasUserChanged()` delegates to `isEqualTo()`
first, which compares two *users* and never sees the token. The
functional coverage therefore runs a user class without it - see
`ImpersonationTokenRefreshTest` - and asserts a follow-up request, since
the enter response itself is issued before any refresh happens.

Enter: JSON body `{"identifier": "<user>"}`; responds 200
`{user, impersonator}`, 400 (bad/missing body), 403 (configured role
missing, or a listener vetoed by throwing `AccessDeniedException`), 404
(unknown target), 409 (already impersonating - checked *before* the
role check, since the impersonated user typically lacks the role and a
SwitchUserToken can only exist after a successful enter - or
self-impersonation). Exit: no body; 200 `{user}` or 409 (not
impersonating). The target resolves through the app's user provider
(the autowiring alias that exists with exactly one configured provider;
multi-provider apps rebind the controller's provider argument).

Events: Symfony fires the same `SwitchUserEvent` for entering and
exiting, which forces listeners to sniff request parameters to tell the
directions apart. The bundle therefore dispatches its own
`ImpersonationEnteredEvent` / `ImpersonationExitedEvent` - each fires
only for its direction, and guard listeners veto by throwing
`AccessDeniedException` - plus the standard `SwitchUserEvent` for
compatibility with existing listeners.

### 7. CSRF, logout, login conveniences

**CSRF**: bearer-carried sessions have no ambient credential - a
cross-site page cannot make the victim's browser attach the token - so
classic CSRF does not apply. A decorator over
`security.csrf.token_manager` makes `isTokenValid()` return true for
requests on bridged firewalls (one seam covers form-login, logout and
app-level checks), delegating everywhere else. On by default
(`csrf_bypass: false` to keep validation); apps without
symfony/security-csrf simply have nothing to decorate.

**Logout**: plain `logout:` firewall config is supported - the session
is invalidated (F6) and the cookie-clearing headers are suppressed like
any other session cookie. Opt-in `logout.json_response: true` answers
204 No Content instead of the default redirect, above Symfony's
redirect listener but replaceable by app listeners. A logout response
advertises a fresh anonymous token for the post-logout session,
consistently with the client contract (§4).

**Login responder** (`LoginController`, opt-in): mounted as the
firewall's `json_login` check_path; the authenticator handles the
credentials, this shapes the success response as
`{user, roles, token}` (+ `expires_in` when a lifetime is configured) -
the token in the body for clients that prefer it over the header. On a
lazy firewall the session only starts when the security context is
persisted, *after* the controller, so it starts the session itself to
fix the id early enough to mint from.

### 8. Extension events and enhancement patterns

Two events form the extension surface for stricter token semantics:

- **`VerifySessionTokenEvent`** - dispatched before the firewall for a
  presented token whose session is live; listeners call
  `revoke(?reason)`. A revoked token flows into the stale-token
  signalling; the session record itself is *preserved*, because under
  token-embedded expiry multiple tokens can share one session and
  killing the session for one token would break the others. A listener
  wanting the whole session dead calls
  `$event->getSession()->invalidate()` as well. Dispatched only when a
  listener is registered, because registering one makes the bridge
  start the session eagerly on token-presenting requests -
  pay-for-what-you-use.
- **`SessionTokenMintedEvent`** - dispatched at every mint with the new
  token's *claims* (never the encoded token) and a reason: `anonymous`,
  `login` (advertisement/login-controller, by authentication state) or
  `refresh`. One request may mint more than once (login body + header).

Reference implementations live in the test fixtures and share the same
check hook; only their stamping differs. The stamped fields are
ordinary app-owned session data, with the fragility that implies - that
trade sits with the app, by construction:

- *Early revocation after refresh*
  (`tests/.../RevokeSupersededTokensListener`): the token's `expiresAt`
  doubles as its generation marker - on a `refresh`-reason mint, stamp
  `newest_expiry` + `superseded_at`; on verify, revoke tokens expiring
  before `newest_expiry` once `superseded_at + grace` passes.
  Same-second refreshes tie and deliberately survive (the
  concurrent-refresh race).
- *Hard session-age cap* (`tests/.../SessionAgeCapListener`): stamp
  `created_at` on Symfony's own `LoginSuccessEvent` (fires after the
  login migration - no bundle hook needed); on verify, revoke past
  `created_at + max_age` and invalidate the session outright. Because
  the guard runs pre-firewall, the refresh endpoint is automatically
  covered - an aged-out session cannot refresh its way past the cap.
- *Mint-policy tripwire* (`tests/.../UnexpectedTokenMintListener`): a
  `SessionTokenMintedEvent` listener with a route→reason allowlist that
  throws (→ 500) when a token is minted outside the app's
  token-issuing endpoints - for apps returning tokens in JSON bodies
  who want stray session creation to fail loudly rather than strand
  clients with tokens they never saw. Its allowlist encodes the
  pitfalls: login mints twice (body + header); logout's response
  advertises a fresh anonymous token; stale-token 401s advertise
  replacement tokens on arbitrary routes (skip via the stale
  attribute); per-request authenticators (Basic, OIDC access tokens)
  mint wherever they authenticate - the surprise the tripwire exists to
  catch. It throws only once per request, because the 500 error
  response itself triggers another advertisement which must pass for
  the error page to render.

Subclassing was considered as the extension mechanism and rejected:
classes stay `final` (composition over inheritance, no BC surface from
protected methods); service decoration remains the escape hatch for
exotic needs.

### 9. Configuration

```yaml
# config/packages/api_session.yaml
api_session:
    firewalls: []                 # firewall names to bridge (required)
    token:
        response_header: X-Session-Token   # null to disable
        prefix: sess_             # non-empty, dot-free
        lifetime: null            # seconds; non-null enables refresh (§5)
    csrf_bypass: true             # disable CSRF on bridged firewalls
    stale_token:
        www_authenticate: true    # RFC 6750 invalid_token on 401 (§2)
    logout:
        json_response: false      # opt-in: 204 on logout instead of redirect
    switch_user:
        role: ROLE_ALLOWED_TO_SWITCH
        grant_previous_admin_role: auto   # auto | true | false (§6)
```

The header itself is fixed to `Authorization: Bearer`; switch-user needs
no `enabled` flag because it only exists where the app mounts the
controllers.
