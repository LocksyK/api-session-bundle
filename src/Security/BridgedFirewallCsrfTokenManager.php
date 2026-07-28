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

namespace LocksyK\ApiSessionBundle\Security;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Decorates the CSRF token manager so validation always passes on bridged
 * firewalls: a bearer-carried session has no ambient credential, so a
 * cross-site page cannot make the victim's browser attach it - classic
 * CSRF does not apply. Registered only when api_session.csrf_bypass is
 * true (the default).
 */
final class BridgedFirewallCsrfTokenManager implements CsrfTokenManagerInterface
{
    public function __construct(
        private readonly CsrfTokenManagerInterface $inner,
        private readonly BridgedFirewallResolver $firewalls,
        private readonly RequestStack $requestStack,
    ) {
    }

    public function getToken(string $tokenId): CsrfToken
    {
        return $this->inner->getToken($tokenId);
    }

    public function refreshToken(string $tokenId): CsrfToken
    {
        return $this->inner->refreshToken($tokenId);
    }

    public function removeToken(string $tokenId): ?string
    {
        return $this->inner->removeToken($tokenId);
    }

    public function isTokenValid(CsrfToken $token): bool
    {
        $request = $this->requestStack->getMainRequest();
        if (null !== $request && $this->firewalls->isBridged($request)) {
            return true;
        }

        return $this->inner->isTokenValid($token);
    }
}
