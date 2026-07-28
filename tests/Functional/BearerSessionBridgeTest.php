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

final class BearerSessionBridgeTest extends WebTestCase
{
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = self::createClient();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testAnonymousSessionMintsTokenAndNoCookie(): void
    {
        $response = $this->anon('alpha');

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertNotNull($this->token($response));
        self::assertSame([], $response->headers->all('set-cookie'), 'Bridged responses must not set cookies.');
    }

    public function testPresentedTokenResumesTheSession(): void
    {
        $token = $this->token($this->anon('alpha'));
        self::assertNotNull($token);

        $response = $this->anon('beta', $token);

        self::assertSame('alpha', $this->json($response)['previous'], 'Session state must carry across requests via the token.');
        self::assertNull($this->token($response), 'An unchanged session must not re-advertise a token.');
    }

    public function testSessionCookieIsIgnoredOnTheBridgedFirewall(): void
    {
        $token = $this->token($this->anon('alpha'));
        self::assertNotNull($token);

        // sess_<sid>.<mac> - recover the sid and present it as a cookie
        // instead of a bearer token: it must NOT resume the session.
        $sid = explode('.', substr($token, \strlen('sess_')))[0];

        $this->client->getCookieJar()->set(new \Symfony\Component\BrowserKit\Cookie('MOCKSESSID', $sid));
        $response = $this->anon('gamma');

        self::assertNull($this->json($response)['previous'], 'A session cookie must not resume a session on a bridged firewall.');
        self::assertNotSame($token, $this->token($response));
    }

    public function testLoginRotatesTheToken(): void
    {
        $anonToken = $this->token($this->anon('alpha'));
        self::assertNotNull($anonToken);

        $this->client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret'], [
            'HTTP_AUTHORIZATION' => 'Bearer '.$anonToken,
        ]);
        $response = $this->client->getResponse();

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame('alice', $this->json($response)['user']);

        $loginToken = $this->token($response);
        self::assertNotNull($loginToken, 'Login must advertise a fresh token.');
        self::assertNotSame($anonToken, $loginToken, 'Login must rotate the token (session fixation).');

        self::assertSame('alice', $this->whoami($loginToken), 'The rotated token must authenticate.');
        self::assertNull($this->whoami($anonToken), 'The pre-login token must be dead after login.');
    }

    public function testLoginControllerBodyCarriesUserRolesAndToken(): void
    {
        $this->client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret']);
        $response = $this->client->getResponse();

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $body = $this->json($response);
        self::assertSame('alice', $body['user']);
        self::assertSame(['ROLE_USER'], $body['roles']);
        self::assertSame($this->token($response), $body['token'], 'The body token must match the response header.');
    }

    public function testMissingAndGarbageCredentialsAreUnauthorized(): void
    {
        $this->client->request('GET', '/api/whoami');
        self::assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());

        $this->client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer not-one-of-ours']);
        self::assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());
    }

    public function testOtherAuthorizationSchemesCoexist(): void
    {
        // Same firewall, same header - HTTP Basic must still work, and the
        // stateful firewall then stores the token in a session whose bearer
        // token the response advertises.
        $this->client->request('GET', '/api/whoami', server: [
            'PHP_AUTH_USER' => 'alice',
            'PHP_AUTH_PW' => 'secret',
        ]);
        $response = $this->client->getResponse();

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame('alice', $this->json($response)['user']);

        $token = $this->token($response);
        self::assertNotNull($token);
        self::assertSame('alice', $this->whoami($token), 'The session minted for a Basic-auth login must be resumable by token.');
    }

    public function testLogoutInvalidatesTheToken(): void
    {
        $this->client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret']);
        $token = $this->token($this->client->getResponse());
        self::assertNotNull($token);
        self::assertSame('alice', $this->whoami($token));

        $this->client->request('POST', '/api/logout', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
        $logoutResponse = $this->client->getResponse();
        self::assertSame(Response::HTTP_NO_CONTENT, $logoutResponse->getStatusCode(), 'Opted-in JSON logout must answer 204 instead of a redirect.');
        self::assertSame([], $logoutResponse->headers->all('set-cookie'), 'Logout must not leak session cookies either.');

        self::assertNull($this->whoami($token), 'The token must be unusable after logout.');
    }

    private function anon(string $challenge, ?string $token = null): Response
    {
        $server = null !== $token ? ['HTTP_AUTHORIZATION' => 'Bearer '.$token] : [];
        $this->client->jsonRequest('POST', '/api/anon', ['challenge' => $challenge], $server);

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

    private function token(Response $response): ?string
    {
        return $response->headers->get('X-Session-Token');
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
