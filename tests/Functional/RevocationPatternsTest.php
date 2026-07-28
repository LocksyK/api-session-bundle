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

namespace LocksyK\ApiSessionBundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Proves the two revocation enhancement patterns work as app-side
 * listeners on VerifySessionTokenEvent / SessionTokenMintedEvent /
 * LoginSuccessEvent (DESIGN.md §8). Both kernel environments run
 * with token.lifetime = 4s, so every revocation asserted here happens
 * BEFORE the token's own embedded expiry - proving it was the listener,
 * not the lifetime.
 */
final class RevocationPatternsTest extends WebTestCase
{
    private const BEARER_CHALLENGE = 'Bearer error="invalid_token"';

    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testSupersededTokenIsRevokedAfterItsGraceWindow(): void
    {
        $client = self::createClient(['environment' => 'revocation']);
        $oldToken = $this->login($client);

        // A same-second refresh would (deliberately) tie the generation
        // marker; wait so the new token provably expires later.
        sleep(1);

        $client->request('POST', '/api/refresh', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$oldToken]);
        self::assertSame(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        $body = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        $newToken = $body['token'] ?? null;
        self::assertIsString($newToken);

        self::assertSame('alice', $this->whoami($client, $oldToken), 'Within the grace window the superseded token must still work.');

        sleep(2); // grace (1s) over; old token's own expiry (4s from login) not yet reached

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$oldToken]);
        $revoked = $client->getResponse();
        self::assertSame(Response::HTTP_UNAUTHORIZED, $revoked->getStatusCode(), 'Past the grace window the superseded token must be revoked - before its own expiry.');
        self::assertContains(self::BEARER_CHALLENGE, $revoked->headers->all('www-authenticate'));

        self::assertSame('alice', $this->whoami($client, $newToken), 'The newest-generation token must be unaffected.');
    }

    public function testSessionAgeCapRevokesEvenUnexpiredTokens(): void
    {
        $client = self::createClient(['environment' => 'agecap']);
        $token = $this->login($client);

        self::assertSame('alice', $this->whoami($client, $token));

        sleep(3); // cap (2s) exceeded; token's own expiry (4s) not yet reached

        // Refresh cannot extend past the cap: the guard runs before the
        // firewall, so the request never reaches the controller.
        $client->request('POST', '/api/refresh', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $refresh = $client->getResponse();
        self::assertSame(Response::HTTP_UNAUTHORIZED, $refresh->getStatusCode(), 'An age-capped session must not be refreshable.');
        self::assertContains(self::BEARER_CHALLENGE, $refresh->headers->all('www-authenticate'));

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $capped = $client->getResponse();
        self::assertSame(Response::HTTP_UNAUTHORIZED, $capped->getStatusCode(), 'The age cap must revoke the session before the token\'s own expiry.');
        self::assertContains(self::BEARER_CHALLENGE, $capped->headers->all('www-authenticate'));
    }

    private function login(KernelBrowser $client): string
    {
        $client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret']);
        $token = $client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($token);

        return $token;
    }

    private function whoami(KernelBrowser $client, string $token): ?string
    {
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $response = $client->getResponse();

        if (Response::HTTP_OK !== $response->getStatusCode()) {
            return null;
        }

        $data = json_decode((string) $response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        $user = $data['user'] ?? null;
        \assert(null === $user || \is_string($user));

        return $user;
    }
}
