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
use LocksyK\ApiSessionBundle\Event\VerifySessionTokenEvent;

/**
 * Reference implementation of the "early revocation after refresh"
 * enhancement pattern (DESIGN.md §8): after a refresh, tokens of
 * older generations die once a grace window passes, instead of living
 * to their own embedded expiry.
 *
 * The token's expiresAt doubles as its generation marker - a refreshed
 * token always expires later than its predecessor (equal only for
 * same-second refreshes, which deliberately survive: that is the
 * concurrent-refresh race the grace exists for). The stamped fields are
 * ordinary app-owned session data.
 */
final class RevokeSupersededTokensListener
{
    public const NEWEST_EXPIRY_KEY = 'app_newest_token_expiry';
    public const SUPERSEDED_AT_KEY = 'app_superseded_at';
    public const GRACE_PERIOD = 1;

    public function onTokenMinted(SessionTokenMintedEvent $event): void
    {
        if (SessionTokenMintedEvent::REASON_REFRESH !== $event->getReason()) {
            return;
        }

        $session = $event->getSession();
        $session->set(self::NEWEST_EXPIRY_KEY, $event->getToken()->expiresAt);
        $session->set(self::SUPERSEDED_AT_KEY, time());
    }

    public function onVerifyToken(VerifySessionTokenEvent $event): void
    {
        $session = $event->getSession();
        $newestExpiry = $session->get(self::NEWEST_EXPIRY_KEY);
        $supersededAt = $session->get(self::SUPERSEDED_AT_KEY);
        $expiresAt = $event->getToken()->expiresAt;

        if (!\is_int($newestExpiry) || !\is_int($supersededAt) || null === $expiresAt) {
            return;
        }

        if ($expiresAt < $newestExpiry && time() > $supersededAt + self::GRACE_PERIOD) {
            $event->revoke('superseded by a newer token');
        }
    }
}
