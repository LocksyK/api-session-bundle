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

use LocksyK\ApiSessionBundle\Event\ImpersonationEnteredEvent;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * A guard listener vetoing certain impersonation targets - without any
 * request-parameter sniffing, since ImpersonationEnteredEvent only ever
 * fires for entering.
 */
final class DenyBobImpersonationListener
{
    public function __invoke(ImpersonationEnteredEvent $event): void
    {
        if ('bob' === $event->getTargetUser()->getUserIdentifier()) {
            throw new AccessDeniedException('bob may not be impersonated.');
        }
    }
}
