# ApiSessionBundle

Stateful Symfony firewalls for API endpoints: the session id travels in
the `Authorization: Bearer` header instead of a cookie.

> **Status: pre-release.** Feature-complete against its design
> ([`DESIGN.md`](DESIGN.md)) and fully tested, but not yet
> tagged or published to Packagist.

## Why

Stateless token schemes (JWT & friends) give up what server-side
sessions provide for free: instant revocation, server-side state, idle
expiry, no claims-refresh problem. This bundle keeps Symfony's ordinary
session machinery - it just moves the session id out of the cookie and
into a bearer token:

- **Bearer-token sessions** - no `Set-Cookie` on API responses, ever;
  session cookies sent by clients are ignored. The token is handed to
  the client at login and presented as `Authorization: Bearer <token>`.
- **Pre-authentication sessions work** - a session created before login
  (a WebAuthn challenge, OIDC state, a CSRF-protected form) gets a token
  too, and login rotates it (fixation protection included).
- **Explicit switch-user endpoints** - impersonation only exists on
  routes the app mounts; the generic `_switch_user` parameter never
  works.
- **Coexistence** - tokens the bundle doesn't recognise (OIDC access
  tokens, HTTP Basic, API keys) pass through untouched to the rest of
  the authenticator chain on the same firewall.
- **Optional absolute lifetime + refresh** - expiry is embedded and
  signed in the token itself; no server-side bookkeeping to corrupt.

Requirements: PHP >= 8.2, Symfony 6.4 LTS, 7.x or 8.x (Symfony 8
requires PHP >= 8.4).

## Installation

```bash
composer require locksyk/api-session-bundle
```

Enable the bundle (Flex does this automatically):

```php
// config/bundles.php
LocksyK\ApiSessionBundle\ApiSessionBundle::class => ['all' => true],
```

## Quick start

Keep your firewall exactly as it would be for cookie sessions - any
authenticator works (`json_login`, WebAuthn, OIDC, custom):

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            provider: app_users
            json_login: { check_path: api_login }
            logout: { path: api_logout }
```

Then bridge it:

```yaml
# config/packages/api_session.yaml
api_session:
    firewalls: [api]
    logout: { json_response: true }   # 204 instead of a redirect
```

Optionally mount the ready-made login responder (the authenticator still
handles credentials; this shapes the success response):

```yaml
# config/routes.yaml
api_login:
    path: /api/login
    methods: POST
    controller: LocksyK\ApiSessionBundle\Controller\LoginController
api_logout:
    path: /api/logout
    methods: POST
```

That's it. Log in and the response carries the session token in the
`X-Session-Token` header (and, with `LoginController`, in the body as
`{user, roles, token}`); present it on every request:

```
Authorization: Bearer sess_k3f9...a1.Zm9v...bar
```

## The client contract

- Whenever a response carries the token header (`X-Session-Token` by
  default), it announces the **current** token - store it and use it
  from then on. In practice the token changes at anonymous-session
  creation and at login; a refresh (below) mints an *additional* token.
- A `401` carrying `WWW-Authenticate: Bearer error="invalid_token"`
  (RFC 6750) means the presented token was genuinely one of ours but is
  no longer usable - expired or its session is gone. Discard it and
  re-authenticate. A plain `401` without that header means no (valid)
  credentials were presented at all.
- No cookies are involved in either direction.

Pre-authentication flows work naturally: e.g. a WebAuthn ceremony calls
`POST /api/auth/options` (server stores the challenge in a fresh
anonymous session → response carries its token), then presents that
token on `POST /api/auth/verify`; the login success response carries the
rotated, authenticated token.

## Configuration reference

```yaml
api_session:
    firewalls: []                  # firewall names to bridge (required)
    token:
        response_header: X-Session-Token   # null to disable the header
        prefix: sess_              # token prefix; non-empty, dot-free
        lifetime: null             # seconds; non-null enables refresh
    csrf_bypass: true              # CSRF check bypass on bridged firewalls
    stale_token:
        www_authenticate: true     # RFC 6750 invalid_token on 401s
    logout:
        json_response: false       # opt-in: 204 on logout
    switch_user:
        role: ROLE_ALLOWED_TO_SWITCH
```

## Token format

The default strategy signs the claims with HMAC-SHA256, keyed by a
derivation of `kernel.secret` (rotating the secret invalidates all
outstanding tokens):

```
without lifetime: <prefix><session-id>.<mac>
with lifetime:    <prefix><session-id>.<unix-expiry>.<mac>
```

The MAC covers the expiry, so clients may read it (to refresh
proactively) but cannot alter it. A leaked session-store key is not a
usable credential - building a token requires the app secret.

## Absolute lifetime and refresh

By default tokens live as long as their session (sliding idle expiry).
Setting `token.lifetime` embeds a signed absolute expiry in every minted
token, enforced *before the session is ever touched*. Mount the refresh
endpoint to let clients extend their stay:

```yaml
api_refresh:
    path: /api/refresh
    methods: POST
    controller: LocksyK\ApiSessionBundle\Controller\RefreshTokenController
```

`POST /api/refresh` with a valid token returns
`{token, expires_in}` - an **additional** token for the same session
with a fresh expiry. Notes:

- Refresh does **not** revoke the previous token; it remains valid until
  its own expiry. Revocation is what logout/session invalidation is for:
  the session dies, killing every outstanding token at once. (See
  "Enhancement patterns" for stricter semantics.)
- Concurrent refreshes from racing client threads are harmless.
- Sessions have no built-in cap on total age under active refresh.

## Logout

Symfony's plain `logout:` firewall config works as-is - the session is
invalidated, so every token for it dies instantly, and no stray cookie
headers leak. `logout.json_response: true` answers `204 No Content`
instead of the default redirect; your own `LogoutEvent` listeners can
still replace the response.

## Impersonation (switch-user)

Do **not** enable Symfony's `switch_user` firewall option. Mount the
endpoints instead - nothing impersonation-related exists unless you do:

```yaml
api_impersonate:
    path: /api/impersonate
    methods: POST
    controller: LocksyK\ApiSessionBundle\Controller\EnterImpersonationController
api_impersonate_exit:
    path: /api/impersonate
    methods: DELETE
    controller: LocksyK\ApiSessionBundle\Controller\ExitImpersonationController
```

`POST` with `{"identifier": "<user>"}` enters impersonation (requires
`switch_user.role`; the impersonation token carries the target's roles,
and `IS_IMPERSONATOR` and friends behave as usual); `DELETE` exits.
Responses: `400` bad body, `403` missing role or listener veto, `404`
unknown target, `409` already/not impersonating.

The token also carries `ROLE_PREVIOUS_ADMIN` on Symfony 6.4 only,
matching what that version's built-in `switch_user` did. Symfony 7.0
dropped the convention on both sides at once - `SwitchUserListener`
stopped granting the role, and `ContextListener` stopped expecting it -
so on 7.0+ the role must be absent or the token's roles no longer match
the reloaded user's and the session is deauthenticated on the next
request. Check `IS_IMPERSONATOR` rather than the role in your own
voters; it works on every supported version.

Guard listeners subscribe to the bundle's `ImpersonationEnteredEvent` /
`ImpersonationExitedEvent` - each fires only for its direction, so no
request-parameter sniffing - and veto by throwing
`AccessDeniedException`. Symfony's `SwitchUserEvent` is also dispatched
for existing listeners. The target is resolved through your user
provider (the autowiring alias when exactly one is configured;
multi-provider apps rebind the controller's provider argument).

## Stale-token signalling

When a presented token verifies as ours but is no longer usable, three
signals fire:

- request attribute `StaleTokenDetector::STALE_ATTRIBUTE` - computed
  before your entry point runs, so it can distinguish "session expired,
  log in again" from "no credentials";
- `WWW-Authenticate: Bearer error="invalid_token"` appended to the 401
  (disable with `stale_token.www_authenticate: false`);
- a `StaleSessionTokenEvent` for telemetry, once per request.

## CSRF

Bearer-carried sessions have no ambient credential, so classic CSRF
does not apply; by default the bundle bypasses CSRF validation on
bridged firewalls (form-login, logout, and app-level checks alike)
while leaving the rest of the app untouched. Set `csrf_bypass: false`
to keep validation.

## Custom token strategies

Alias `LocksyK\ApiSessionBundle\Token\TokenStrategyInterface` to
your own service to change the token encoding - e.g. authenticated
encryption that hides the session id from the client entirely:

```php
interface TokenStrategyInterface
{
    public function mint(string $sessionId, ?int $expiresAt = null): string;
    public function extract(string $bearerValue): ?SessionToken;
}
```

**Security contract:** every claim - session id *and* expiry - must be
integrity-protected. The bridge enforces expiry from the decoded claims
alone; an encoding that lets a client alter them without detection is
exploitable by construction, and that responsibility sits with the
implementation. Strategies must be able to mint for any session id the
session layer chooses (non-invertible mappings are unsupported).

## Enhancement patterns: revocation

Two events form the extension surface for stricter token semantics:

- `VerifySessionTokenEvent` - dispatched before the firewall for a
  presented token whose session is live; call `revoke(?reason)` to
  reject it into the stale-token signalling. The session record is
  preserved (newer tokens may share it); invalidate it yourself for a
  full kill. Dispatched only when listened to - registering a listener
  makes the bridge start sessions eagerly on token-presenting requests.
- `SessionTokenMintedEvent` - every mint, with the new token's claims
  and a reason (`anonymous` / `login` / `refresh`), for stamping.

Reference implementations (copy them from the test suite; the stamped
fields are ordinary app-owned session data):

- **Early revocation after refresh** -
  `tests/Functional/Fixture/RevokeSupersededTokensListener.php`:
  superseded tokens die a grace period after a refresh instead of
  living to their own expiry.
- **Hard session-age cap** -
  `tests/Functional/Fixture/SessionAgeCapListener.php`: the session
  dies N seconds after login no matter how often it refreshes; the
  pre-firewall guard means refresh can't extend past the cap.
- **Mint-policy tripwire** -
  `tests/Functional/Fixture/UnexpectedTokenMintListener.php`: an app
  that returns tokens in JSON bodies on known endpoints 500s if a
  token is ever minted on any other route, catching stray session
  creation (e.g. a per-request authenticator persisting a session on
  an arbitrary route) before clients silently lose tokens they never
  saw. Encodes the allowlist gotchas: login mints twice, logout's
  response advertises a fresh anonymous token, stale-token 401s mint
  replacements anywhere (skipped via the stale attribute), and the
  throw happens once per request so the error response can render.

## License

GNU General Public License, version 2 only (GPL-2.0-only).
See [LICENSE](LICENSE).
