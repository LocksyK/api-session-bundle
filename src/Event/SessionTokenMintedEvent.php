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
 * Dispatched every time the bundle mints a token: when a response
 * advertises one (reason "anonymous" or "login", depending on whether
 * the request is authenticated), from the opt-in login controller
 * ("login"), and from the refresh endpoint ("refresh"). One request may
 * mint more than once (e.g. login body + response header).
 *
 * Carries the new token's claims, not the encoded token. The session is
 * started; listeners may stamp it (e.g. to later judge older tokens in
 * VerifySessionTokenEvent).
 */
final class SessionTokenMintedEvent extends Event
{
    public const REASON_ANONYMOUS = 'anonymous';
    public const REASON_LOGIN = 'login';
    public const REASON_REFRESH = 'refresh';

    public function __construct(
        private readonly Request $request,
        private readonly SessionInterface $session,
        private readonly SessionToken $token,
        private readonly string $reason,
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
     * One of the REASON_* constants.
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
