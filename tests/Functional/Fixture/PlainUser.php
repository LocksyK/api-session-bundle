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

namespace LocksyK\ApiSessionBundle\Tests\Functional\Fixture;

use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A user that deliberately does *not* implement EquatableInterface, the
 * way an app's own entity typically doesn't.
 *
 * InMemoryUser does implement it, and its isEqualTo() compares the two
 * *users'* roles - never the token's - so it short-circuits
 * ContextListener::hasUserChanged() before the token-role check that
 * governs whether an impersonation token survives the next request. Any
 * fixture built on InMemoryUser is therefore blind to that check.
 */
final class PlainUser implements UserInterface, PasswordAuthenticatedUserInterface
{
    /**
     * @param non-empty-string $identifier
     * @param list<string>     $roles
     */
    public function __construct(
        private readonly string $identifier,
        private readonly string $password,
        private readonly array $roles,
    ) {
    }

    /**
     * @return non-empty-string
     */
    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * Required by UserInterface up to Symfony 7.4; dropped from it in 8.0,
     * where this is simply an unused method.
     */
    public function eraseCredentials(): void
    {
    }
}
