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
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Opt-in (api_session.logout.json_response): answers logout on bridged
 * firewalls with 204 No Content instead of Symfony's default redirect.
 * Runs above Symfony's DefaultLogoutListener (priority 64); app listeners
 * at lower priorities can still replace the response.
 */
final class JsonLogoutResponseListener
{
    public const PRIORITY = 100;

    public function __construct(
        private readonly BridgedFirewallResolver $firewalls,
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        if (null !== $event->getResponse() || !$this->firewalls->isBridged($event->getRequest())) {
            return;
        }

        $event->setResponse(new JsonResponse(null, Response::HTTP_NO_CONTENT));
    }
}
