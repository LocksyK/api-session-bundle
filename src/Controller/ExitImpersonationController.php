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

use LocksyK\ApiSessionBundle\Event\ImpersonationExitedEvent;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Exits impersonation, restoring the original (impersonator) token. The
 * app mounts this on a route of its choosing, e.g. DELETE on the same
 * path the enter controller is mounted on.
 */
final class ExitImpersonationController
{
    use JsonErrorTrait;

    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly BridgedFirewallResolver $firewalls,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $this->firewalls->requireStatefulFirewall($request);

        $token = $this->tokenStorage->getToken();
        if (!$token instanceof SwitchUserToken) {
            return $this->error(Response::HTTP_CONFLICT, 'Not impersonating.');
        }

        $exitedUser = $token->getUser() ?? throw new \LogicException('An impersonation token always has a user.');
        $original = $token->getOriginalToken();
        $resumedUser = $original->getUser() ?? throw new \LogicException('An impersonation token always wraps an authenticated token.');

        try {
            $this->eventDispatcher->dispatch(new ImpersonationExitedEvent($request, $exitedUser, $resumedUser));
            $this->eventDispatcher->dispatch(new SwitchUserEvent($request, $resumedUser, $original), SecurityEvents::SWITCH_USER);
        } catch (AccessDeniedException $e) {
            return $this->error(Response::HTTP_FORBIDDEN, '' !== $e->getMessage() ? $e->getMessage() : 'Exiting impersonation denied.');
        }

        $this->tokenStorage->setToken($original);

        return new JsonResponse(['user' => $original->getUserIdentifier()]);
    }
}
