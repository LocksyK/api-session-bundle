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

namespace LocksyK\ApiSessionBundle\EventListener;

use LocksyK\ApiSessionBundle\Event\VerifySessionTokenEvent;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use LocksyK\ApiSessionBundle\Security\StaleTokenDetector;
use LocksyK\ApiSessionBundle\Token\TokenStrategyInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Feeds the session id from "Authorization: Bearer <token>" into the
 * session subsystem before anything can start the session, and makes sure
 * the session cookie is never honoured on a bridged firewall.
 *
 * A token whose embedded expiry has passed is rejected here, before the
 * session is ever touched, and flows into the stale-token signalling.
 */
final class BearerSessionRequestListener implements EventSubscriberInterface
{
    /**
     * Request attribute holding the session id extracted from the presented
     * bearer token, when a valid, unexpired one was presented.
     */
    public const PRESENTED_SID_ATTRIBUTE = '_api_session_presented_sid';

    /**
     * After the framework's SessionListener has attached the session
     * factory (priority 128), before the firewall (priority 8) can start
     * the session.
     */
    public const PRIORITY = 24;

    private const AUTHORIZATION_HEADER = 'Authorization';
    private const BEARER_SCHEME = 'Bearer ';

    public function __construct(
        private readonly BridgedFirewallResolver $firewalls,
        private readonly TokenStrategyInterface $tokens,
        private readonly StaleTokenDetector $staleTokens,
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['onKernelRequest', self::PRIORITY]];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$this->firewalls->isBridgedMainRequest($event)) {
            return;
        }

        $request = $event->getRequest();
        $session = $request->getSession();
        if ($session->isStarted()) {
            return;
        }

        $claims = null;
        $header = $request->headers->get(self::AUTHORIZATION_HEADER);
        if (\is_string($header) && str_starts_with($header, self::BEARER_SCHEME)) {
            $claims = $this->tokens->extract(substr($header, \strlen(self::BEARER_SCHEME)));
        }

        if (null !== $claims && null !== $claims->expiresAt && time() > $claims->expiresAt) {
            // Ours, but past its absolute lifetime: signal and treat the
            // request as tokenless - the session is never consulted.
            $this->staleTokens->markStale($request, $claims->sessionId);
            $claims = null;
        }

        if (null === $claims) {
            // No (valid) token: never fall back to a session cookie on a
            // bridged firewall. Forcing a fresh unknown id makes any cookie
            // irrelevant; under native sessions with use_strict_mode the
            // unknown id itself is replaced at start.
            $session->setId(self::freshUnknownSessionId());

            return;
        }

        $session->setId($claims->sessionId);
        // The security ContextListener only restores a token when
        // Request::hasPreviousSession() is true, which checks for the
        // session cookie - mirror the id into the cookie bag so the
        // bearer token counts as a previous session. The explicit
        // setId() above is what the session actually uses.
        $request->cookies->set($session->getName(), $claims->sessionId);
        $request->attributes->set(self::PRESENTED_SID_ATTRIBUTE, $claims->sessionId);

        // App-level token verification (revocation, session age caps):
        // only when someone listens, since it forces an eager session
        // start; and only for live sessions - marker-less ones are
        // already on the stale path.
        if (!$this->eventDispatcher->hasListeners(VerifySessionTokenEvent::class)) {
            return;
        }

        if (!$session->isStarted()) {
            $session->start();
        }
        if (!$session->has(StaleTokenDetector::LIVENESS_KEY)) {
            return;
        }

        $verify = new VerifySessionTokenEvent($request, $session, $claims);
        $this->eventDispatcher->dispatch($verify);
        if ($verify->isRevoked()) {
            $this->detachRevokedSession($session);
            $request->attributes->remove(self::PRESENTED_SID_ATTRIBUTE);
            $this->staleTokens->markStale($request, $claims->sessionId);
        }
    }

    /**
     * Reject the TOKEN, not the session - other (newer) tokens may map
     * to the same record. Persist any listener changes, then point the
     * request at a fresh unknown id. Listeners wanting the whole session
     * dead invalidate it themselves.
     */
    private function detachRevokedSession(SessionInterface $session): void
    {
        $session->save();
        $session->setId(self::freshUnknownSessionId());
    }

    private static function freshUnknownSessionId(): string
    {
        return bin2hex(random_bytes(16));
    }
}
