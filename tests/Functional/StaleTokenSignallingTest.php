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

final class StaleTokenSignallingTest extends WebTestCase
{
    private const BEARER_CHALLENGE = 'Bearer error="invalid_token"';

    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = self::createClient();
        StaleTokenEventRecorder::$sessionIds = [];
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testStaleTokenIsSignalledOn401(): void
    {
        $token = $this->login();
        $this->client->request('POST', '/api/logout', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        $response = $this->whoami($token);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertContains(self::BEARER_CHALLENGE, $response->headers->all('www-authenticate'), 'A recognised-but-dead token must be signalled per RFC 6750.');
        self::assertCount(1, StaleTokenEventRecorder::$sessionIds, 'StaleSessionTokenEvent must fire exactly once.');

        // The signal must repeat on every later use of the dead token.
        $response = $this->whoami($token);
        self::assertContains(self::BEARER_CHALLENGE, $response->headers->all('www-authenticate'));
        self::assertCount(2, StaleTokenEventRecorder::$sessionIds);
    }

    public function testMissingCredentialsAreNotSignalledStale(): void
    {
        $this->client->request('GET', '/api/whoami');
        $response = $this->client->getResponse();

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertNotContains(self::BEARER_CHALLENGE, $response->headers->all('www-authenticate'));
        self::assertSame([], StaleTokenEventRecorder::$sessionIds);
    }

    public function testGarbageTokensAreNotSignalledStale(): void
    {
        $response = $this->whoami('not-one-of-ours');

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertNotContains(self::BEARER_CHALLENGE, $response->headers->all('www-authenticate'));
        self::assertSame([], StaleTokenEventRecorder::$sessionIds);
    }

    public function testLiveAnonymousTokenIsNotSignalledStale(): void
    {
        // A live anonymous session (e.g. mid WebAuthn ceremony) hitting a
        // protected endpoint is a plain 401 - flagging it invalid_token
        // would make clients discard a token they still need.
        $this->client->jsonRequest('POST', '/api/anon', ['challenge' => 'alpha']);
        $anonToken = $this->client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($anonToken);

        $response = $this->whoami($anonToken);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertNotContains(self::BEARER_CHALLENGE, $response->headers->all('www-authenticate'));
        self::assertSame([], StaleTokenEventRecorder::$sessionIds);
    }

    private function login(): string
    {
        $this->client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret']);
        $token = $this->client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($token);

        return $token;
    }

    private function whoami(string $token): Response
    {
        $this->client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        return $this->client->getResponse();
    }
}
