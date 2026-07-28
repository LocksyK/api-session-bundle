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

namespace LocksyK\ApiSessionBundle\Security;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Bundle\SecurityBundle\Security\FirewallConfig;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\KernelEvent;

/**
 * Answers firewall questions about a request. Firewall matching is
 * static (request matchers), so this works before the firewall listener
 * has run.
 */
final class BridgedFirewallResolver
{
    /**
     * @param list<string> $firewalls
     */
    public function __construct(
        private readonly Security $security,
        private readonly array $firewalls,
    ) {
    }

    /**
     * Whether the request belongs to one of the bridged firewalls
     * (api_session.firewalls).
     */
    public function isBridged(Request $request): bool
    {
        $config = $this->security->getFirewallConfig($request);

        return null !== $config && \in_array($config->getName(), $this->firewalls, true);
    }

    /**
     * The shared guard for the bundle's kernel-event listeners: only act
     * on the main request, with a session available, inside a bridged
     * firewall.
     */
    public function isBridgedMainRequest(KernelEvent $event): bool
    {
        if (!$event->isMainRequest()) {
            return false;
        }

        $request = $event->getRequest();

        return $request->hasSession() && $this->isBridged($request);
    }

    /**
     * The firewall config of the request, which must be stateful - for
     * endpoints that manipulate the session-persisted security token.
     *
     * @throws \LogicException when mounted outside any firewall or on a
     *                         stateless one (a configuration error)
     */
    public function requireStatefulFirewall(Request $request): FirewallConfig
    {
        $config = $this->security->getFirewallConfig($request);
        if (null === $config) {
            throw new \LogicException('This endpoint must be mounted inside a firewall.');
        }
        if ($config->isStateless()) {
            throw new \LogicException(\sprintf('This endpoint needs a stateful firewall; "%s" is stateless.', $config->getName()));
        }

        return $config;
    }
}
