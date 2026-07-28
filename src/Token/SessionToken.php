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
 * The claims carried by a bearer token: the session id and, optionally,
 * an absolute expiry (unix timestamp; null = no absolute expiry, the
 * session's own idle expiry still applies).
 */
final class SessionToken
{
    public function __construct(
        public readonly string $sessionId,
        public readonly ?int $expiresAt = null,
    ) {
    }
}
