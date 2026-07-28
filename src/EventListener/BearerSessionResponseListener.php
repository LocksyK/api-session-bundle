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

use LocksyK\ApiSessionBundle\Event\SessionTokenMintedEvent;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use LocksyK\ApiSessionBundle\Security\StaleTokenDetector;
use LocksyK\ApiSessionBundle\Token\SessionTokenIssuer;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Advertises the current session token in a response header whenever the
 * session id no longer matches the presented token (anonymous session
 * creation, login migration), and keeps the session out of cookie land.
 */
final class BearerSessionResponseListener implements EventSubscriberInterface
{
    /**
     * Before the framework's session listener (priority -1000) saves the
     * session, while isStarted() still reflects request-time usage and the
     * id is final.
     */
    public const ADVERTISE_PRIORITY = -900;

    /**
     * After the framework's session listener may have attached the session
     * cookie (or logout's clearing cookie), so both get stripped.
     */
    public const STRIP_COOKIE_PRIORITY = -1050;

    private const WWW_AUTHENTICATE_HEADER = 'WWW-Authenticate';

    /**
     * RFC 6750: the client's token was ours but is no longer usable.
     */
    private const STALE_TOKEN_CHALLENGE = 'Bearer error="invalid_token"';

    public function __construct(
        private readonly BridgedFirewallResolver $firewalls,
        private readonly SessionTokenIssuer $tokenIssuer,
        private readonly StaleTokenDetector $staleTokens,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly ?string $responseHeader,
        private readonly bool $staleWwwAuthenticate,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => [
            ['advertiseToken', self::ADVERTISE_PRIORITY],
            ['stripSessionCookie', self::STRIP_COOKIE_PRIORITY],
        ]];
    }

    public function advertiseToken(ResponseEvent $event): void
    {
        if (!$this->firewalls->isBridgedMainRequest($event)) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();

        if (Response::HTTP_UNAUTHORIZED === $response->getStatusCode()
            && $this->staleWwwAuthenticate
            && $this->staleTokens->isStale($request)
        ) {
            // Appended (not replaced) so other challenges - e.g. a Basic
            // one from the entry point - survive.
            $response->headers->set(self::WWW_AUTHENTICATE_HEADER, self::STALE_TOKEN_CHALLENGE, false);
        }

        $session = $request->getSession();
        if (!$session->isStarted()) {
            return;
        }

        $sessionId = $session->getId();
        $presentedSid = $request->attributes->get(BearerSessionRequestListener::PRESENTED_SID_ATTRIBUTE);

        // A dead id adopted by a lenient session storage keeps the
        // presented id AND a stale verdict - never mark such a record
        // live. Any other started session earns the liveness marker.
        $adoptedDeadId = $presentedSid === $sessionId
            && true === $request->attributes->get(StaleTokenDetector::STALE_ATTRIBUTE);
        if (!$adoptedDeadId) {
            $session->set(StaleTokenDetector::LIVENESS_KEY, true);
        }

        if ($presentedSid === $sessionId) {
            // The client already holds the token for this session.
            return;
        }

        if (null !== $this->responseHeader) {
            $reason = null !== $this->tokenStorage->getToken()
                ? SessionTokenMintedEvent::REASON_LOGIN
                : SessionTokenMintedEvent::REASON_ANONYMOUS;
            $response->headers->set($this->responseHeader, $this->tokenIssuer->issue($request, $session, $reason));
        }
    }

    public function stripSessionCookie(ResponseEvent $event): void
    {
        if (!$this->firewalls->isBridgedMainRequest($event)) {
            return;
        }

        $request = $event->getRequest();
        $sessionName = $request->getSession()->getName();
        $response = $event->getResponse();
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === $sessionName) {
                $response->headers->removeCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
            }
        }
    }
}
