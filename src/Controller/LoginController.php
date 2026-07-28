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
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use LocksyK\ApiSessionBundle\Token\SessionTokenIssuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Opt-in login responder for simple setups: mount it on the firewall's
 * json_login check_path and the authenticator handles the credentials -
 * this only shapes the success response, returning the authenticated
 * user, its roles, and (on a bridged firewall) the session token in the
 * body for clients that prefer it over the response header.
 */
final class LoginController
{
    use JsonErrorTrait;

    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
        private readonly BridgedFirewallResolver $firewalls,
        private readonly SessionTokenIssuer $tokenIssuer,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $token = $this->tokenStorage->getToken();
        $user = $token?->getUser();
        if (null === $token || null === $user) {
            return $this->error(Response::HTTP_UNAUTHORIZED, 'Authentication required.');
        }

        $payload = [
            'user' => $user->getUserIdentifier(),
            'roles' => $token->getRoleNames(),
        ];

        if ($this->firewalls->isBridged($request) && $request->hasSession()) {
            $session = $request->getSession();
            if (!$session->isStarted()) {
                // On a lazy firewall the session only starts when the
                // security context is persisted, *after* this controller.
                // Login always ends with a persisted session, so starting
                // it now just fixes the id early enough to mint from.
                $session->start();
            }
            $payload['token'] = $this->tokenIssuer->issue($request, $session, SessionTokenMintedEvent::REASON_LOGIN);
            if (null !== $this->tokenIssuer->getLifetime()) {
                $payload['expires_in'] = $this->tokenIssuer->getLifetime();
            }
        }

        return new JsonResponse($payload);
    }
}
