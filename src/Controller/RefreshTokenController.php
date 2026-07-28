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

namespace LocksyK\ApiSessionBundle\Controller;

use LocksyK\ApiSessionBundle\Event\SessionTokenMintedEvent;
use LocksyK\ApiSessionBundle\EventListener\BearerSessionRequestListener;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use LocksyK\ApiSessionBundle\Security\StaleTokenDetector;
use LocksyK\ApiSessionBundle\Token\SessionTokenIssuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Mints an additional token for the presented token's session, expiring
 * a full token.lifetime from now. The session itself is untouched: no
 * migration, no server-side bookkeeping. The previous token is NOT
 * revoked - it remains valid until its own embedded expiry (revocation
 * is what logout/session invalidation is for, and that kills every
 * outstanding token of the session at once).
 *
 * The app mounts this on a route of its choosing; it only functions
 * when an absolute lifetime (token.lifetime) is configured - without
 * one, sliding idle expiry needs no refresh.
 */
final class RefreshTokenController
{
    use JsonErrorTrait;

    public function __construct(
        private readonly BridgedFirewallResolver $firewalls,
        private readonly StaleTokenDetector $staleTokens,
        private readonly SessionTokenIssuer $tokenIssuer,
        private readonly ?string $responseHeader,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $this->firewalls->requireStatefulFirewall($request);
        if (!$this->firewalls->isBridged($request)) {
            throw new \LogicException('The refresh endpoint must be mounted inside a bridged firewall (api_session.firewalls).');
        }
        if (null === $this->tokenIssuer->getLifetime()) {
            throw new \LogicException('Token refresh requires an absolute lifetime; set api_session.token.lifetime.');
        }

        if (!\is_string($request->attributes->get(BearerSessionRequestListener::PRESENTED_SID_ATTRIBUTE))) {
            return $this->error(Response::HTTP_BAD_REQUEST, 'A session token must be presented to refresh.');
        }

        if ($this->staleTokens->isStale($request)) {
            return $this->error(Response::HTTP_UNAUTHORIZED, 'The session token is no longer valid.');
        }

        $token = $this->tokenIssuer->issue($request, $request->getSession(), SessionTokenMintedEvent::REASON_REFRESH);

        $response = new JsonResponse([
            'token' => $token,
            'expires_in' => $this->tokenIssuer->getLifetime(),
        ]);
        if (null !== $this->responseHeader) {
            $response->headers->set($this->responseHeader, $token);
        }

        return $response;
    }
}
