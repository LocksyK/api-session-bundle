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

use LocksyK\ApiSessionBundle\Token\SessionToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched before the firewall runs, for a presented token whose
 * session exists and is live - the app's chance to veto it (token
 * revocation, session age caps, …). A revoked token is rejected into
 * the stale-token signalling; its session record is preserved, since
 * other (newer) tokens may map to the same session.
 *
 * Only dispatched when at least one listener is registered; registering
 * one makes the bridge start the session eagerly on token-presenting
 * requests. Listeners typically judge session fields they stamped
 * earlier (via SessionTokenMintedEvent or LoginSuccessEvent) - such
 * fields are ordinary app-owned session data, with the fragility that
 * implies; see DESIGN.md "Extension events and enhancement patterns".
 */
final class VerifySessionTokenEvent extends Event
{
    private bool $revoked = false;
    private ?string $reason = null;

    public function __construct(
        private readonly Request $request,
        private readonly SessionInterface $session,
        private readonly SessionToken $token,
    ) {
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function getSession(): SessionInterface
    {
        return $this->session;
    }

    public function getToken(): SessionToken
    {
        return $this->token;
    }

    /**
     * Reject the presented token: the request is treated as having
     * presented a stale token. The session record itself is preserved -
     * other (newer) tokens may still map to it; a listener that wants
     * the whole session dead calls $event->getSession()->invalidate()
     * as well.
     */
    public function revoke(?string $reason = null): void
    {
        $this->revoked = true;
        $this->reason ??= $reason;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }
}
