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

use Symfony\Component\Security\Http\Event\SwitchUserEvent;

/**
 * Records Symfony SwitchUserEvent dispatches to prove compatibility with
 * listeners written for the built-in switch_user feature.
 */
final class SwitchUserEventRecorder
{
    /**
     * @var list<string>
     */
    public static array $targets = [];

    /**
     * Role names of the token each dispatch carried, which is the only
     * place to observe them: on security-http 7.0+ a token carrying
     * ROLE_PREVIOUS_ADMIN does not survive into the next request.
     *
     * @var list<list<string>>
     */
    public static array $tokenRoles = [];

    public function __invoke(SwitchUserEvent $event): void
    {
        $token = $event->getToken();

        self::$targets[] = $event->getTargetUser()->getUserIdentifier();
        // A null token would be a listener having unset it; record the
        // empty role set and let the asserting test say so.
        self::$tokenRoles[] = null === $token ? [] : array_values($token->getRoleNames());
    }
}
