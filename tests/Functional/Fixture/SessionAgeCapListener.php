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

use LocksyK\ApiSessionBundle\Event\VerifySessionTokenEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Reference implementation of the "hard cap on total session age"
 * enhancement pattern (DESIGN.md §8): no matter how often tokens
 * are refreshed, the session dies MAX_AGE seconds after login.
 *
 * Stamping needs no bundle hook - Symfony's LoginSuccessEvent fires
 * after the login session migration, so the stamp lands in the right
 * record. The stamped field is ordinary app-owned session data.
 */
final class SessionAgeCapListener
{
    public const CREATED_AT_KEY = 'app_session_created_at';
    public const MAX_AGE = 2;

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $request = $event->getRequest();
        if (!$request->hasSession()) {
            return;
        }

        $session = $request->getSession();
        if (!\is_int($session->get(self::CREATED_AT_KEY))) {
            $session->set(self::CREATED_AT_KEY, time());
        }
    }

    public function onVerifyToken(VerifySessionTokenEvent $event): void
    {
        $createdAt = $event->getSession()->get(self::CREATED_AT_KEY);
        if (\is_int($createdAt) && time() > $createdAt + self::MAX_AGE) {
            $event->revoke('session age cap reached');
            // Unlike per-token revocation, an aged-out session is dead for
            // every token - destroy the record too.
            $event->getSession()->invalidate();
        }
    }
}
