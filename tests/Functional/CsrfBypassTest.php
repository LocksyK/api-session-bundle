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

final class CsrfBypassTest extends WebTestCase
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

    public function testCsrfValidationIsBypassedOnTheBridgedFirewall(): void
    {
        $this->client->jsonRequest('POST', '/api/login', ['username' => 'alice', 'password' => 'secret']);
        $token = $this->client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($token);

        self::assertTrue($this->probe('/api/csrf-probe', $token), 'CSRF must be bypassed on bridged firewalls: bearer sessions have no ambient credential.');
    }

    public function testCsrfValidationStillAppliesOutsideBridgedFirewalls(): void
    {
        self::assertFalse($this->probe('/csrf-probe', null), 'Outside bridged firewalls the real CSRF validation must run.');
    }

    private function probe(string $path, ?string $token): bool
    {
        $server = null !== $token ? ['HTTP_AUTHORIZATION' => 'Bearer '.$token] : [];
        $this->client->jsonRequest('POST', $path, ['_token' => 'utter-garbage'], $server);
        $response = $this->client->getResponse();

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertIsBool($data['valid'] ?? null);

        return $data['valid'];
    }
}
