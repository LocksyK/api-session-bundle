<?php

declare(strict_types=1);

/*
 * This file is part of the ApiSessionBundle package.
 *
 * (c) Kris Shannon <kris@shannon.id.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

namespace LocksyK\ApiSessionBundle\Token;

/**
 * Default strategy:
 *   without expiry: "<prefix><sid>.<mac>"
 *   with expiry:    "<prefix><sid>.<unix-expiry>.<mac>"
 * where the base64url HMAC-SHA256 covers the session id and (when
 * present) the expiry, so neither can be altered by the client.
 *
 * The signature also means a leaked session-store key is not a usable
 * credential - building the Authorization header requires the app
 * secret. Rotating the secret invalidates all outstanding tokens.
 */
final class HmacTokenStrategy implements TokenStrategyInterface
{
    /**
     * Domain-separation context so the raw kernel secret is never used
     * directly as the MAC key.
     */
    private const KEY_DERIVATION_CONTEXT = 'locksyk/api-session-bundle:token-strategy';

    /**
     * Separates the claims inside a token; forbidden in the prefix and
     * session id so the MAC payload stays boundary-unambiguous.
     */
    private const CLAIM_SEPARATOR = '.';

    private readonly string $key;

    public function __construct(
        #[\SensitiveParameter] string $secret,
        private readonly string $prefix = 'sess_',
    ) {
        if ('' === $secret) {
            throw new \InvalidArgumentException('The HMAC token strategy requires a non-empty secret (kernel.secret).');
        }
        if ('' === $prefix) {
            throw new \InvalidArgumentException('The token prefix must not be empty; it is what keeps these tokens cheaply distinguishable from other bearer schemes.');
        }
        if (str_contains($prefix, self::CLAIM_SEPARATOR)) {
            throw new \InvalidArgumentException('The token prefix must not contain ".".');
        }

        $this->key = hash_hmac('sha256', self::KEY_DERIVATION_CONTEXT, $secret, true);
    }

    public function mint(string $sessionId, ?int $expiresAt = null): string
    {
        if ('' === $sessionId) {
            throw new \InvalidArgumentException('Cannot mint a token for an empty session id.');
        }
        if (str_contains($sessionId, self::CLAIM_SEPARATOR)) {
            throw new \InvalidArgumentException('Cannot mint a token for a session id containing "." - it is the claim separator.');
        }
        if (null !== $expiresAt && $expiresAt < 0) {
            throw new \InvalidArgumentException('The expiry must be a non-negative unix timestamp.');
        }

        $payload = null === $expiresAt ? $sessionId : $sessionId.self::CLAIM_SEPARATOR.$expiresAt;

        return $this->prefix.$payload.self::CLAIM_SEPARATOR.$this->signature($payload);
    }

    public function extract(string $bearerValue): ?SessionToken
    {
        if (!str_starts_with($bearerValue, $this->prefix)) {
            return null;
        }

        $parts = explode(self::CLAIM_SEPARATOR, substr($bearerValue, \strlen($this->prefix)));
        $count = \count($parts);
        if (2 !== $count && 3 !== $count) {
            return null;
        }

        $signature = array_pop($parts);
        $sessionId = $parts[0];
        $expiresAt = $parts[1] ?? null;
        if ('' === $sessionId || '' === $signature) {
            return null;
        }
        if (null !== $expiresAt && !ctype_digit($expiresAt)) {
            return null;
        }

        $payload = implode(self::CLAIM_SEPARATOR, $parts);
        if (!hash_equals($this->signature($payload), $signature)) {
            return null;
        }

        return new SessionToken($sessionId, null === $expiresAt ? null : (int) $expiresAt);
    }

    private function signature(string $payload): string
    {
        $mac = hash_hmac('sha256', $payload, $this->key, true);

        // base64url without padding keeps the token free of characters that
        // are awkward in an Authorization header.
        return rtrim(strtr(base64_encode($mac), '+/', '-_'), '=');
    }
}
