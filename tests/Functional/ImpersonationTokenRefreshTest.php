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

use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\PlainUserProvider;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Puts the impersonation token through ContextListener's refresh, which
 * is where a wrong role set silently deauthenticates the session: enter
 * answers 200, and every request after it 401s.
 *
 * Runs against the "plainuser" environment, whose user class does not
 * implement EquatableInterface. That matters - InMemoryUser does, and its
 * isEqualTo() returns before hasUserChanged() ever compares the token's
 * roles, so the default fixture cannot see this class of bug at all.
 */
final class ImpersonationTokenRefreshTest extends WebTestCase
{
    protected function setUp(): void
    {
        PlainUserProvider::$roleOverrides = [];
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        PlainUserProvider::$roleOverrides = [];

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testAnImpersonatedSessionSurvivesTheFollowingRequests(): void
    {
        $client = self::createClient(['environment' => 'plainuser']);
        $token = $this->login($client);

        self::assertSame(Response::HTTP_OK, $this->enter($client, $token, 'alice')->getStatusCode());

        // The refresh the enter response never exercises: the token now
        // comes back out of the session and is checked against the user
        // the provider reloads.
        self::assertSame('alice', $this->whoami($client, $token), 'The impersonation must outlive the request that started it.');
        self::assertSame('alice', $this->whoami($client, $token), 'A re-stored impersonation token must keep refreshing cleanly.');

        self::assertSame(Response::HTTP_OK, $this->exit($client, $token)->getStatusCode());

        self::assertSame('admin', $this->whoami($client, $token), 'The restored impersonator token must refresh cleanly too.');
    }

    public function testARoleChangeStillDeauthenticatesAnImpersonatedSession(): void
    {
        $client = self::createClient(['environment' => 'plainuser']);
        $token = $this->login($client);

        self::assertSame(Response::HTTP_OK, $this->enter($client, $token, 'alice')->getStatusCode());
        self::assertSame('alice', $this->whoami($client, $token));

        // Re-role the impersonated user behind the session's back. The
        // token's roles and the reloaded user's roles now genuinely
        // disagree, which must still end the session - dropping
        // ROLE_PREVIOUS_ADMIN must not blunt that check.
        PlainUserProvider::$roleOverrides['alice'] = ['ROLE_USER', 'ROLE_EDITOR'];

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode(), 'A role change must still deauthenticate.');
    }

    private function login(KernelBrowser $client): string
    {
        $client->jsonRequest('POST', '/api/login', ['username' => 'admin', 'password' => 'secret']);
        $token = $client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($token);

        return $token;
    }

    private function enter(KernelBrowser $client, string $token, string $identifier): Response
    {
        $client->jsonRequest('POST', '/api/impersonate', ['identifier' => $identifier], [
            'HTTP_AUTHORIZATION' => 'Bearer '.$token,
        ]);

        return $client->getResponse();
    }

    private function exit(KernelBrowser $client, string $token): Response
    {
        $client->request('DELETE', '/api/impersonate', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        return $client->getResponse();
    }

    private function whoami(KernelBrowser $client, string $token): ?string
    {
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $response = $client->getResponse();

        if (Response::HTTP_OK !== $response->getStatusCode()) {
            return null;
        }

        $content = $response->getContent();
        self::assertNotFalse($content);
        $data = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        $user = $data['user'];
        \assert(null === $user || \is_string($user));

        return $user;
    }
}
