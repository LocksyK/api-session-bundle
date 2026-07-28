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
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched before impersonation ends, from the exit endpoint only.
 */
final class ImpersonationExitedEvent extends Event
{
    public function __construct(
        private readonly Request $request,
        private readonly UserInterface $exitedUser,
        private readonly UserInterface $resumedUser,
    ) {
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * The user that was being impersonated.
     */
    public function getExitedUser(): UserInterface
    {
        return $this->exitedUser;
    }

    /**
     * The user control returns to (the impersonator).
     */
    public function getResumedUser(): UserInterface
    {
        return $this->resumedUser;
    }
}
