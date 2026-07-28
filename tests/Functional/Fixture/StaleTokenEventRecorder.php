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

use LocksyK\ApiSessionBundle\Event\StaleSessionTokenEvent;

/**
 * Records StaleSessionTokenEvent dispatches (the stale session ids).
 */
final class StaleTokenEventRecorder
{
    /**
     * @var list<string>
     */
    public static array $sessionIds = [];

    public function __invoke(StaleSessionTokenEvent $event): void
    {
        self::$sessionIds[] = $event->getSessionId();
    }
}
