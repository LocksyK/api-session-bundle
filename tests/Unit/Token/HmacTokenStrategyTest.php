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

namespace LocksyK\ApiSessionBundle\Tests\Unit\Token;

use LocksyK\ApiSessionBundle\Token\HmacTokenStrategy;
use PHPUnit\Framework\TestCase;

final class HmacTokenStrategyTest extends TestCase
{
    private HmacTokenStrategy $strategy;

    protected function setUp(): void
    {
        $this->strategy = new HmacTokenStrategy('unit-test-secret');
    }

    public function testNonExpiringTokenRoundTrips(): void
    {
        $token = $this->strategy->mint('abc123DEF456');

        self::assertStringStartsWith('sess_', $token);
        $claims = $this->strategy->extract($token);
        self::assertNotNull($claims);
        self::assertSame('abc123DEF456', $claims->sessionId);
        self::assertNull($claims->expiresAt);
    }

    public function testExpiringTokenRoundTrips(): void
    {
        $token = $this->strategy->mint('abc123DEF456', 1_800_000_000);

        $claims = $this->strategy->extract($token);
        self::assertNotNull($claims);
        self::assertSame('abc123DEF456', $claims->sessionId);
        self::assertSame(1_800_000_000, $claims->expiresAt);
    }

    public function testForeignValuesAreNotOurs(): void
    {
        // A JWT-shaped value must fall through for other authenticators.
        self::assertNull($this->strategy->extract('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln'));
        self::assertNull($this->strategy->extract('some-opaque-api-key'));
        self::assertNull($this->strategy->extract(''));
        self::assertNull($this->strategy->extract('sess_'));
        self::assertNull($this->strategy->extract('sess_no-signature-part'));
        self::assertNull($this->strategy->extract('sess_.only-signature'));
        self::assertNull($this->strategy->extract('sess_sid.notdigits.c2ln'));
        self::assertNull($this->strategy->extract('sess_sid.1.2.toomanyparts'));
    }

    public function testTamperedSessionIdIsRejected(): void
    {
        $token = $this->strategy->mint('abc123DEF456', 1_800_000_000);
        $tampered = str_replace('sess_abc', 'sess_xyz', $token);

        self::assertNull($this->strategy->extract($tampered));
    }

    public function testTamperedExpiryIsRejected(): void
    {
        $token = $this->strategy->mint('abc123DEF456', 1_800_000_000);
        $tampered = str_replace('.1800000000.', '.1900000000.', $token);

        self::assertNotSame($token, $tampered);
        self::assertNull($this->strategy->extract($tampered), 'A client must not be able to extend its own expiry.');
    }

    public function testStrippingTheExpiryIsRejected(): void
    {
        $token = $this->strategy->mint('abc123DEF456', 1_800_000_000);
        $stripped = str_replace('.1800000000', '', $token);

        self::assertNull($this->strategy->extract($stripped), 'An expiring token must not degrade into a non-expiring one.');
    }

    public function testTamperedSignatureIsRejected(): void
    {
        $token = $this->strategy->mint('abc123DEF456');
        $tampered = substr($token, 0, -4).'AAAA';

        self::assertNull($this->strategy->extract($tampered));
    }

    public function testTokenFromAnotherSecretIsRejected(): void
    {
        $other = new HmacTokenStrategy('a-different-secret');

        self::assertNull($this->strategy->extract($other->mint('abc123DEF456')));
    }

    public function testCustomPrefixSeparatesTokenSpaces(): void
    {
        $other = new HmacTokenStrategy('unit-test-secret', 'app1_');
        $token = $other->mint('abc123DEF456');

        self::assertStringStartsWith('app1_', $token);
        self::assertSame('abc123DEF456', $other->extract($token)?->sessionId);
        self::assertNull($this->strategy->extract($token), 'A differently-prefixed token must fall through.');
        self::assertNull($other->extract($this->strategy->mint('abc123DEF456')));
    }

    public function testLeakedSessionIdAloneIsNotACredential(): void
    {
        // Knowing the raw sid must not let an attacker build the token.
        self::assertNull($this->strategy->extract('sess_abc123DEF456.'.base64_encode(hash('sha256', 'abc123DEF456', true))));
        self::assertNull($this->strategy->extract('sess_abc123DEF456.abc123DEF456'));
    }

    public function testInvalidConstructionsAreRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new HmacTokenStrategy('');
    }

    public function testDottedPrefixIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new HmacTokenStrategy('secret', 'has.dot_');
    }

    public function testEmptyPrefixIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new HmacTokenStrategy('secret', '');
    }

    public function testEmptySessionIdCannotBeMinted(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->strategy->mint('');
    }

    public function testDottedSessionIdCannotBeMinted(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->strategy->mint('has.dot');
    }
}
