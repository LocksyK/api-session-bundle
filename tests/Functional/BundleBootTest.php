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

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

final class BundleBootTest extends KernelTestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        // Symfony's ErrorHandler leaves an exception handler registered after
        // kernel boot (symfony/symfony#53812); PHPUnit flags that as risky.
        restore_exception_handler();
    }

    public function testKernelBootsWithBundleEnabled(): void
    {
        self::bootKernel();

        $container = self::getContainer();

        self::assertSame(['api'], $container->getParameter('api_session.firewalls'));
        self::assertSame('X-Session-Token', $container->getParameter('api_session.token.response_header'));
        self::assertSame('sess_', $container->getParameter('api_session.token.prefix'));
        self::assertNull($container->getParameter('api_session.token.lifetime'));
        self::assertTrue($container->getParameter('api_session.csrf_bypass'));
        self::assertTrue($container->getParameter('api_session.stale_token.www_authenticate'));
        self::assertTrue($container->getParameter('api_session.logout.json_response'));
        self::assertSame('ROLE_ALLOWED_TO_SWITCH', $container->getParameter('api_session.switch_user.role'));
    }
}
