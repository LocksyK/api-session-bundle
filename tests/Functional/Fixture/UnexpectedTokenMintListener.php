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

namespace LocksyK\ApiSessionBundle\Tests\Functional\Fixture;

use LocksyK\ApiSessionBundle\Event\SessionTokenMintedEvent;
use LocksyK\ApiSessionBundle\Security\StaleTokenDetector;

/**
 * Reference implementation of the "mint-policy tripwire" enhancement
 * pattern (DESIGN.md §8): an app returning tokens in JSON bodies
 * on known endpoints fails loudly (500) if a token is ever minted on
 * any other route - catching stray session creation before clients
 * silently lose tokens they never saw.
 *
 * Allowlist gotchas encoded below: login mints twice (body + header,
 * both reason "login"); logout invalidates the session, so its response
 * advertises a fresh ANONYMOUS token; and per-request authenticators
 * (HTTP Basic, OIDC access tokens) mint on whatever route they
 * authenticate - which is exactly the kind of surprise this exists to
 * catch.
 */
final class UnexpectedTokenMintListener
{
    public const VIOLATION_ATTRIBUTE = 'app_unexpected_token_mint';

    private const EXPECTED = [
        'api_anon' => [SessionTokenMintedEvent::REASON_ANONYMOUS],
        'api_login' => [SessionTokenMintedEvent::REASON_LOGIN],
        'api_logout' => [SessionTokenMintedEvent::REASON_ANONYMOUS],
    ];

    public function __invoke(SessionTokenMintedEvent $event): void
    {
        $request = $event->getRequest();

        // Throw only once per request: the 500 error response triggers
        // another advertise mint, which must pass so the error renders.
        if (true === $request->attributes->get(self::VIOLATION_ATTRIBUTE)) {
            return;
        }

        // A stale-token 401 advertises a replacement anonymous token on
        // whatever route was hit - expected noise, not a leak. (Only
        // reachable with storages that regenerate dead ids; the mock
        // storage used in tests adopts them and never re-mints.)
        if (true === $request->attributes->get(StaleTokenDetector::STALE_ATTRIBUTE)) {
            return;
        }

        $route = $request->attributes->get('_route');
        if (\is_string($route) && \in_array($event->getReason(), self::EXPECTED[$route] ?? [], true)) {
            return;
        }

        $request->attributes->set(self::VIOLATION_ATTRIBUTE, true);

        throw new \LogicException(\sprintf('Session token minted on route "%s" (reason "%s") outside the token-issuing endpoints.', \is_string($route) ? $route : '(unrouted)', $event->getReason()));
    }
}
