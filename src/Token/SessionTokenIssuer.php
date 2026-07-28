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

namespace LocksyK\ApiSessionBundle\Token;

use LocksyK\ApiSessionBundle\Event\SessionTokenMintedEvent;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * The single place a token comes into existence: applies the configured
 * absolute lifetime (token.lifetime) and dispatches
 * SessionTokenMintedEvent, so no mint can bypass either.
 *
 * Also the service for apps that hand out tokens from their own
 * endpoints (e.g. in the JSON body of a challenge response): inject it
 * and call issue() with the appropriate reason.
 */
final class SessionTokenIssuer
{
    public function __construct(
        private readonly TokenStrategyInterface $tokens,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly ?int $tokenLifetime,
    ) {
    }

    /**
     * Mint a token for the session's current id and announce it.
     *
     * @param string $reason one of the SessionTokenMintedEvent::REASON_*
     *                       constants
     *
     * @return string the encoded bearer token
     */
    public function issue(Request $request, SessionInterface $session, string $reason): string
    {
        $sessionId = $session->getId();
        $expiresAt = null === $this->tokenLifetime ? null : time() + $this->tokenLifetime;
        $token = $this->tokens->mint($sessionId, $expiresAt);

        $this->eventDispatcher->dispatch(new SessionTokenMintedEvent($request, $session, new SessionToken($sessionId, $expiresAt), $reason));

        return $token;
    }

    /**
     * The configured absolute token lifetime in seconds; null when
     * tokens live as long as their session (sliding idle expiry only).
     */
    public function getLifetime(): ?int
    {
        return $this->tokenLifetime;
    }
}
