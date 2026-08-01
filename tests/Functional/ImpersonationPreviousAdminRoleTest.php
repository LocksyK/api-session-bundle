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

/**
 * switch_user.grant_previous_admin_role overrides the version guess in
 * both directions - the escape hatch for installs where http-kernel's
 * major does not match security-http's.
 *
 * The roles are read off the dispatched SwitchUserEvent rather than a
 * follow-up request: whichever setting disagrees with the installed
 * security-http deauthenticates the session on the next request, which is
 * the whole point of the option, so only the enter request itself can see
 * both cases.
 */
final class ImpersonationPreviousAdminRoleTest extends WebTestCase
{
    protected function setUp(): void
    {
        SwitchUserEventRecorder::$tokenRoles = [];
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        SwitchUserEventRecorder::$targets = [];
        SwitchUserEventRecorder::$tokenRoles = [];

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testTheRoleIsGrantedWhenForcedOn(): void
    {
        $this->enterImpersonation('prevadminon');

        self::assertContains('ROLE_PREVIOUS_ADMIN', SwitchUserEventRecorder::$tokenRoles[0]);
    }

    public function testTheRoleIsWithheldWhenForcedOff(): void
    {
        $this->enterImpersonation('prevadminoff');

        self::assertNotContains('ROLE_PREVIOUS_ADMIN', SwitchUserEventRecorder::$tokenRoles[0]);
        self::assertContains('ROLE_USER', SwitchUserEventRecorder::$tokenRoles[0], 'The target\'s own roles must still be carried.');
    }

    private function enterImpersonation(string $environment): void
    {
        $client = self::createClient(['environment' => $environment]);
        $token = $this->login($client);

        $client->jsonRequest('POST', '/api/impersonate', ['identifier' => 'alice'], [
            'HTTP_AUTHORIZATION' => 'Bearer '.$token,
        ]);

        self::assertSame(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        self::assertCount(1, SwitchUserEventRecorder::$tokenRoles);
    }

    private function login(KernelBrowser $client): string
    {
        $client->jsonRequest('POST', '/api/login', ['username' => 'admin', 'password' => 'secret']);
        $token = $client->getResponse()->headers->get('X-Session-Token');
        self::assertNotNull($token);

        return $token;
    }
}
