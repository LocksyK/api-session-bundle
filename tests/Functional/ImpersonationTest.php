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

use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\SwitchUserEventRecorder;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

final class ImpersonationTest extends WebTestCase
{
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = self::createClient();
        SwitchUserEventRecorder::$targets = [];
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testEnterAndExitImpersonation(): void
    {
        $token = $this->login('admin');

        $response = $this->enter($token, 'alice');
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame(['user' => 'alice', 'impersonator' => 'admin'], $this->json($response));
        self::assertNull($response->headers->get('X-Session-Token'), 'Impersonation must not rotate the session token.');

        self::assertSame('alice', $this->whoami($token), 'The impersonation must persist in the session across requests.');

        $response = $this->exit($token);
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame(['user' => 'admin'], $this->json($response));

        self::assertSame('admin', $this->whoami($token));

        self::assertSame(['alice', 'admin'], SwitchUserEventRecorder::$targets, 'Symfony SwitchUserEvent must fire on enter and exit for BC listeners.');
    }

    public function testEnteringRequiresTheConfiguredRole(): void
    {
        $token = $this->login('alice');

        $response = $this->enter($token, 'admin');

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        self::assertSame('alice', $this->whoami($token));
        self::assertSame([], SwitchUserEventRecorder::$targets);
    }

    public function testListenersCanVetoATarget(): void
    {
        $token = $this->login('admin');

        $response = $this->enter($token, 'bob');

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        self::assertSame('bob may not be impersonated.', $this->json($response)['error']);
        self::assertSame('admin', $this->whoami($token), 'A vetoed impersonation must leave the token untouched.');
    }

    public function testUnknownTargetIsNotFound(): void
    {
        $token = $this->login('admin');

        self::assertSame(Response::HTTP_NOT_FOUND, $this->enter($token, 'nobody')->getStatusCode());
    }

    public function testMissingIdentifierIsBadRequest(): void
    {
        $token = $this->login('admin');

        $this->client->jsonRequest('POST', '/api/impersonate', [], ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        self::assertSame(Response::HTTP_BAD_REQUEST, $this->client->getResponse()->getStatusCode());
    }

    public function testSelfImpersonationConflicts(): void
    {
        $token = $this->login('admin');

        self::assertSame(Response::HTTP_CONFLICT, $this->enter($token, 'admin')->getStatusCode());
    }

    public function testNestedImpersonationConflicts(): void
    {
        $token = $this->login('admin');
        $this->enter($token, 'alice');

        self::assertSame(Response::HTTP_CONFLICT, $this->enter($token, 'alice')->getStatusCode());
    }

    public function testExitWithoutImpersonatingConflicts(): void
    {
        $token = $this->login('admin');

        self::assertSame(Response::HTTP_CONFLICT, $this->exit($token)->getStatusCode());
    }

    private function login(string $username): string
    {
        $this->client->jsonRequest('POST', '/api/login', ['username' => $username, 'password' => 'secret']);
        $token = $this->client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($token);

        return $token;
    }

    private function enter(string $token, string $identifier): Response
    {
        $this->client->jsonRequest('POST', '/api/impersonate', ['identifier' => $identifier], [
            'HTTP_AUTHORIZATION' => 'Bearer '.$token,
        ]);

        return $this->client->getResponse();
    }

    private function exit(string $token): Response
    {
        $this->client->request('DELETE', '/api/impersonate', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        return $this->client->getResponse();
    }

    private function whoami(string $token): ?string
    {
        $this->client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $response = $this->client->getResponse();

        if (Response::HTTP_OK !== $response->getStatusCode()) {
            return null;
        }

        $user = $this->json($response)['user'];
        \assert(null === $user || \is_string($user));

        return $user;
    }

    /**
     * @return array<mixed>
     */
    private function json(Response $response): array
    {
        $content = $response->getContent();
        self::assertNotFalse($content);
        $data = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        return $data;
    }
}
