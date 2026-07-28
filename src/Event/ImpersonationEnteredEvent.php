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
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched before impersonation starts, from the enter endpoint only -
 * unlike Symfony's SwitchUserEvent (also dispatched, for compatibility),
 * this never fires for an exit, so listeners can guard entering without
 * sniffing request parameters.
 *
 * Throw AccessDeniedException from a listener to veto (the endpoint
 * responds 403).
 */
final class ImpersonationEnteredEvent extends Event
{
    public function __construct(
        private readonly Request $request,
        private readonly UserInterface $targetUser,
        private readonly TokenInterface $originalToken,
    ) {
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function getTargetUser(): UserInterface
    {
        return $this->targetUser;
    }

    public function getOriginalToken(): TokenInterface
    {
        return $this->originalToken;
    }
}
