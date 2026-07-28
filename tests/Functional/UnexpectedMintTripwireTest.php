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
 * Proves the mint-policy tripwire enhancement pattern (DESIGN.md
 * §8, Fixture\UnexpectedTokenMintListener): mints on the allowlisted
 * token-issuing routes pass, a mint anywhere else is a 500.
 */
final class UnexpectedMintTripwireTest extends WebTestCase
{
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = self::createClient(['environment' => 'minttrap']);
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testMintsOnTheTokenIssuingRoutesPass(): void
    {
        // Anonymous session (webauthn-challenge analogue).
        $this->client->jsonRequest('POST', '/api/anon', ['challenge' => 'alpha']);
        $response = $this->client->getResponse();
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $anonToken = $response->headers->get('X-Session-Token');
        self::assertNotNull($anonToken);

        // Login (two mints on this route: body + header, both allowed).
        $this->client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret'], [
            'HTTP_AUTHORIZATION' => 'Bearer '.$anonToken,
        ]);
        $response = $this->client->getResponse();
        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $loginToken = $response->headers->get('X-Session-Token');
        self::assertNotNull($loginToken);

        // An ordinary request mints nothing - the tripwire stays quiet.
        $this->client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$loginToken]);
        self::assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        // Logout advertises a fresh anonymous token - allowlisted.
        $this->client->request('POST', '/api/logout', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$loginToken]);
        self::assertSame(Response::HTTP_NO_CONTENT, $this->client->getResponse()->getStatusCode());
    }

    public function testAMintOutsideTheAllowlistIsAServerError(): void
    {
        // HTTP Basic authenticates per-request on the stateful firewall:
        // the security context gets persisted, so the response would
        // advertise a token for a session minted on /api/whoami - a
        // route the app never hands tokens out on.
        $this->client->request('GET', '/api/whoami', server: [
            'PHP_AUTH_USER' => 'alice',
            'PHP_AUTH_PW' => 'secret',
        ]);
        $response = $this->client->getResponse();

        self::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        // Quote-free substrings: error-page renderers differ in how they
        // escape the exception message.
        $content = (string) $response->getContent();
        self::assertStringContainsString('Session token minted on route', $content, 'The debug error page must carry the tripwire message.');
        self::assertStringContainsString('api_whoami', $content);
    }
}
