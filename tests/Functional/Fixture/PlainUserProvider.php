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

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Serves PlainUser, so refreshUser() hands ContextListener a user whose
 * roles are compared against the token's.
 *
 * @implements UserProviderInterface<PlainUser>
 */
final class PlainUserProvider implements UserProviderInterface
{
    /**
     * @var array<non-empty-string, list<string>>
     */
    private const USERS = [
        'alice' => ['ROLE_USER'],
        'bob' => ['ROLE_USER'],
        'admin' => ['ROLE_USER', 'ROLE_ALLOWED_TO_SWITCH'],
    ];

    /**
     * Lets a test re-role a user between requests, the way a real store
     * would, so deauthentication-on-role-change stays provable.
     *
     * @var array<string, list<string>>
     */
    public static array $roleOverrides = [];

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        if (!isset(self::USERS[$identifier])) {
            throw new UserNotFoundException(\sprintf('No user "%s".', $identifier));
        }

        return new PlainUser($identifier, 'secret', self::$roleOverrides[$identifier] ?? self::USERS[$identifier]);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof PlainUser) {
            throw new UnsupportedUserException(\sprintf('Unsupported user class "%s".', $user::class));
        }

        // A fresh instance, as a real provider would return - the token
        // keeps holding the deserialised one until it is accepted.
        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return PlainUser::class === $class;
    }
}
