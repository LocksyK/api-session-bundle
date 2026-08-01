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

use LocksyK\ApiSessionBundle\Event\ImpersonationEnteredEvent;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Enters impersonation. The app mounts this on a route of its choosing,
 * e.g. POST /api/impersonate with the body {"identifier": "<user>"} -
 * this endpoint (plus the exit controller) replaces Symfony's switch_user
 * firewall option, which must stay disabled.
 */
final class EnterImpersonationController
{
    use JsonErrorTrait;

    /**
     * Marks an impersonation token so voters can recognise it - the same
     * role Symfony's built-in switch_user granted until security-http 7.0.
     */
    private const ROLE_PREVIOUS_ADMIN = 'ROLE_PREVIOUS_ADMIN';

    /**
     * @param UserProviderInterface<UserInterface>|null $userProvider
     */
    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
        private readonly AuthorizationCheckerInterface $authorizationChecker,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly BridgedFirewallResolver $firewalls,
        private readonly ?UserProviderInterface $userProvider,
        private readonly string $requiredRole,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $firewall = $this->firewalls->requireStatefulFirewall($request);

        // Before the role check: the impersonated user typically lacks the
        // role, and a SwitchUserToken can only exist after a successful
        // enter, so answering 409 first leaks nothing.
        $originalToken = $this->tokenStorage->getToken();
        if ($originalToken instanceof SwitchUserToken) {
            return $this->error(Response::HTTP_CONFLICT, 'Already impersonating; exit first.');
        }

        if (null === $originalToken || !$this->authorizationChecker->isGranted($this->requiredRole)) {
            return $this->error(Response::HTTP_FORBIDDEN, 'Not allowed to impersonate.');
        }

        try {
            $identifier = trim($request->getPayload()->getString('identifier'));
        } catch (\JsonException) {
            return $this->error(Response::HTTP_BAD_REQUEST, 'Request body must be valid JSON.');
        }
        if ('' === $identifier) {
            return $this->error(Response::HTTP_BAD_REQUEST, 'A non-empty "identifier" is required.');
        }
        if ($identifier === $originalToken->getUserIdentifier()) {
            return $this->error(Response::HTTP_CONFLICT, 'Cannot impersonate yourself.');
        }

        if (null === $this->userProvider) {
            throw new \LogicException('No user provider is available for impersonation. Configure exactly one user provider, or rebind the user-provider argument of the "'.self::class.'" service.');
        }

        try {
            $target = $this->userProvider->loadUserByIdentifier($identifier);
        } catch (UserNotFoundException) {
            return $this->error(Response::HTTP_NOT_FOUND, 'No such user.');
        }

        $roles = $target->getRoles();
        if (self::grantsPreviousAdminRole()) {
            $roles[] = self::ROLE_PREVIOUS_ADMIN;
        }
        $token = new SwitchUserToken($target, $firewall->getName(), $roles, $originalToken);

        try {
            $this->eventDispatcher->dispatch(new ImpersonationEnteredEvent($request, $target, $originalToken));
            $switchEvent = new SwitchUserEvent($request, $target, $token);
            $this->eventDispatcher->dispatch($switchEvent, SecurityEvents::SWITCH_USER);
        } catch (AccessDeniedException $e) {
            return $this->error(Response::HTTP_FORBIDDEN, '' !== $e->getMessage() ? $e->getMessage() : 'Impersonation denied.');
        }

        $this->tokenStorage->setToken($switchEvent->getToken() ?? $token);

        return new JsonResponse([
            'user' => $target->getUserIdentifier(),
            'impersonator' => $originalToken->getUserIdentifier(),
        ]);
    }

    /**
     * The ROLE_PREVIOUS_ADMIN convention is all-or-nothing, and it ended
     * with security-http 7.0.
     *
     * Up to 6.4, SwitchUserListener appended the role to the impersonation
     * token *and* ContextListener::hasUserChanged() added it to the role
     * set it expected that token to carry. Both halves were dropped
     * together in 7.0. So a token whose roles disagree with the refreshed
     * user's roles - carrying the role on 7.0+, or omitting it on 6.4 -
     * counts as "user has changed", and the session is silently
     * deauthenticated when the *next* request refreshes it: enter returns
     * 200, everything after it 401s.
     *
     * Note this reads http-kernel's version as a stand-in for
     * security-http's. The two can technically sit on different majors
     * (security-http 6.4 accepts http-kernel ^7.0), which would flip this
     * the wrong way; keeping every Symfony component on one major - the
     * normal arrangement, and what Flex enforces - avoids that.
     */
    private static function grantsPreviousAdminRole(): bool
    {
        return version_compare(Kernel::VERSION, '7.0.0', '<');
    }
}
