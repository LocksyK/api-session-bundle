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

use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\StaleTokenEventRecorder;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs against the "lifetime" kernel environment: token.lifetime = 4s -
 * small enough to wait out expiries in real time.
 */
final class TokenLifetimeTest extends WebTestCase
{
    private const BEARER_CHALLENGE = 'Bearer error="invalid_token"';

    protected function setUp(): void
    {
        StaleTokenEventRecorder::$sessionIds = [];
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testRefreshIssuesAnAdditionalTokenForTheSameSession(): void
    {
        $client = self::createClient(['environment' => 'lifetime']);
        $oldToken = $this->login($client);

        sleep(2);

        $client->request('POST', '/api/refresh', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$oldToken]);
        $response = $client->getResponse();
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());

        $body = json_decode((string) $response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        $newToken = $body['token'] ?? null;
        self::assertIsString($newToken);
        self::assertNotSame($oldToken, $newToken);
        self::assertSame(4, $body['expires_in'] ?? null);
        self::assertSame($newToken, $response->headers->get('X-Session-Token'), 'Refresh must advertise the replacement in the header too.');

        self::assertSame('alice', $this->whoami($client, $newToken));
        self::assertSame('alice', $this->whoami($client, $oldToken), 'Refresh must not revoke the old token; it lives until its own expiry.');

        // Concurrent refreshes are harmless: same session, another token.
        $client->request('POST', '/api/refresh', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$oldToken]);
        self::assertSame(Response::HTTP_OK, $client->getResponse()->getStatusCode());

        sleep(3); // old token (minted t+0, lifetime 4) is now past expiry; new one (minted t+2) is not

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$oldToken]);
        $expired = $client->getResponse();
        self::assertSame(Response::HTTP_UNAUTHORIZED, $expired->getStatusCode(), 'The old token must die at its own embedded expiry.');
        self::assertContains(self::BEARER_CHALLENGE, $expired->headers->all('www-authenticate'));

        self::assertSame('alice', $this->whoami($client, $newToken), 'The refreshed token must outlive the original.');
    }

    public function testAbsoluteLifetimeExpiresTokens(): void
    {
        $client = self::createClient(['environment' => 'lifetime']);
        $token = $this->login($client);

        self::assertSame('alice', $this->whoami($client, $token));

        sleep(5);

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $response = $client->getResponse();
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), 'The token must die at its absolute expiry even though the session was recently used.');
        self::assertContains(self::BEARER_CHALLENGE, $response->headers->all('www-authenticate'));
        self::assertCount(1, StaleTokenEventRecorder::$sessionIds, 'An expired token must dispatch StaleSessionTokenEvent.');
    }

    public function testRefreshWithoutASessionTokenIsRejected(): void
    {
        $client = self::createClient(['environment' => 'lifetime']);

        // Authenticated, but not via a session token (HTTP Basic).
        $client->request('POST', '/api/refresh', server: [
            'PHP_AUTH_USER' => 'alice',
            'PHP_AUTH_PW' => 'secret',
        ]);

        self::assertSame(Response::HTTP_BAD_REQUEST, $client->getResponse()->getStatusCode());
    }

    public function testRefreshRequiresTheLifetimeFeature(): void
    {
        // Default environment: token.lifetime is null.
        $client = self::createClient();
        $token = $this->login($client);

        $client->request('POST', '/api/refresh', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        self::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $client->getResponse()->getStatusCode(), 'Mounting refresh without token.lifetime is a configuration error.');
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
