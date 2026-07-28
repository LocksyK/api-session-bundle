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

namespace LocksyK\ApiSessionBundle\Event;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched (once per request) when a presented bearer token verified as
 * one of ours but is no longer usable - its embedded absolute expiry has
 * passed, or its session no longer exists (idle-expired, logged out,
 * invalidated). Useful for telemetry or for shaping a custom response;
 * the request attribute StaleTokenDetector::STALE_ATTRIBUTE is set to
 * true before this event fires.
 */
final class StaleSessionTokenEvent extends Event
{
    public function __construct(
        private readonly Request $request,
        private readonly string $sessionId,
    ) {
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * The session id the stale token mapped to.
     */
    public function getSessionId(): string
    {
        return $this->sessionId;
    }
}
