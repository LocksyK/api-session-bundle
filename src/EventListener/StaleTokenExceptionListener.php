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

use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use LocksyK\ApiSessionBundle\Security\StaleTokenDetector;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Computes the stale-token verdict when an authentication/authorization
 * failure is about to be handled, so the app's entry point (which the
 * security ExceptionListener calls after us) can read the request
 * attribute and tell "session expired, log in again" apart from "no
 * credentials".
 */
final class StaleTokenExceptionListener implements EventSubscriberInterface
{
    /**
     * Above the security ExceptionListener (priority 1) so the verdict
     * exists before the entry point runs.
     */
    public const PRIORITY = 10;

    public function __construct(
        private readonly BridgedFirewallResolver $firewalls,
        private readonly StaleTokenDetector $staleTokens,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::EXCEPTION => ['onKernelException', self::PRIORITY]];
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $throwable = $event->getThrowable();
        if (!$throwable instanceof AuthenticationException && !$throwable instanceof AccessDeniedException) {
            return;
        }

        if (!$this->firewalls->isBridgedMainRequest($event)) {
            return;
        }

        $this->staleTokens->isStale($event->getRequest());
    }
}
