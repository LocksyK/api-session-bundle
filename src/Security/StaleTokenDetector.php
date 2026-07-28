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

use LocksyK\ApiSessionBundle\Event\StaleSessionTokenEvent;
use LocksyK\ApiSessionBundle\EventListener\BearerSessionRequestListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Decides whether the request's presented bearer token is stale: it
 * verified as one of ours, but its session no longer exists.
 *
 * Detection uses a liveness marker the response listener stamps into
 * every session it saves - id comparison alone cannot distinguish "dead
 * session" from a legitimate login migration, and lenient session
 * storages silently adopt unknown ids. A session reached through a
 * presented token that lacks the marker was therefore never saved by us:
 * the token is stale.
 */
final class StaleTokenDetector
{
    public const LIVENESS_KEY = '_api_session_alive';

    /**
     * Request attribute set to the (bool) staleness verdict once
     * computed; readable by entry points and app listeners.
     */
    public const STALE_ATTRIBUTE = '_api_session_token_stale';

    public function __construct(
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {
    }

    /**
     * Record a stale verdict directly - used for tokens whose staleness
     * is known without consulting the session (an expired embedded
     * expiry). Idempotent; dispatches StaleSessionTokenEvent once.
     */
    public function markStale(Request $request, string $sessionId): void
    {
        if (true === $request->attributes->get(self::STALE_ATTRIBUTE)) {
            return;
        }

        $request->attributes->set(self::STALE_ATTRIBUTE, true);
        $this->eventDispatcher->dispatch(new StaleSessionTokenEvent($request, $sessionId));
    }

    /**
     * Memoized per request; dispatches StaleSessionTokenEvent on the
     * first stale verdict. Starts the session if it isn't started yet.
     */
    public function isStale(Request $request): bool
    {
        if ($request->attributes->has(self::STALE_ATTRIBUTE)) {
            return true === $request->attributes->get(self::STALE_ATTRIBUTE);
        }

        $sessionId = $request->attributes->get(BearerSessionRequestListener::PRESENTED_SID_ATTRIBUTE);
        if (!\is_string($sessionId) || !$request->hasSession()) {
            return false;
        }

        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        if (!$session->has(self::LIVENESS_KEY)) {
            $this->markStale($request, $sessionId);

            return true;
        }

        $request->attributes->set(self::STALE_ATTRIBUTE, false);

        return false;
    }
}
