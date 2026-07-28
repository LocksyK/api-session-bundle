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
 * Encodes and decodes bearer tokens carrying a session id and an
 * optional absolute expiry.
 *
 * A strategy must be able to compute the token for any session id the
 * session layer chooses (mint), so the bundle never has to control
 * session-id selection. This is why a non-invertible mapping (a session
 * id derived by hashing the token) is deliberately unsupported.
 *
 * SECURITY CONTRACT for implementations: every claim in the token -
 * the session id AND the expiry - must be integrity-protected (signed
 * or authenticated-encrypted). The expiry is enforced from the decoded
 * token alone; an encoding that lets a client alter the expiry (or the
 * session id) without detection is exploitable by construction.
 */
interface TokenStrategyInterface
{
    /**
     * Mint the bearer token for a session id.
     *
     * @param int|null $expiresAt unix timestamp after which the token is
     *                            rejected; null for no absolute expiry
     */
    public function mint(string $sessionId, ?int $expiresAt = null): string;

    /**
     * Decode a bearer value into its claims.
     *
     * Returns null when the value is not one of this strategy's tokens
     * (wrong format, bad signature, …) - the Authorization header is then
     * left alone for other authenticators (OIDC access tokens etc.).
     * Expiry is NOT judged here; the bridge enforces it from the claims.
     */
    public function extract(string $bearerValue): ?SessionToken;
}
