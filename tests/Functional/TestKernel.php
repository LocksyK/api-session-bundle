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

use LocksyK\ApiSessionBundle\ApiSessionBundle;
use LocksyK\ApiSessionBundle\Controller\EnterImpersonationController;
use LocksyK\ApiSessionBundle\Controller\ExitImpersonationController;
use LocksyK\ApiSessionBundle\Controller\LoginController;
use LocksyK\ApiSessionBundle\Controller\RefreshTokenController;
use LocksyK\ApiSessionBundle\Event\ImpersonationEnteredEvent;
use LocksyK\ApiSessionBundle\Event\SessionTokenMintedEvent;
use LocksyK\ApiSessionBundle\Event\StaleSessionTokenEvent;
use LocksyK\ApiSessionBundle\Event\VerifySessionTokenEvent;
use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\DenyBobImpersonationListener;
use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\RevokeSupersededTokensListener;
use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\SessionAgeCapListener;
use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\StaleTokenEventRecorder;
use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\SwitchUserEventRecorder;
use LocksyK\ApiSessionBundle\Tests\Functional\Fixture\UnexpectedTokenMintListener;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SecurityBundle(),
            new ApiSessionBundle(),
        ];
    }

    public function getProjectDir(): string
    {
        return sys_get_temp_dir().'/api-session-bundle-tests';
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/api-session-bundle-tests/cache/'.$this->environment;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/api-session-bundle-tests/log';
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test-secret',
            'test' => true,
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
            'csrf_protection' => true,
            'session' => [
                'handler_id' => null,
                'storage_factory_id' => 'session.storage.factory.mock_file',
                'cookie_secure' => 'auto',
                'cookie_samesite' => 'lax',
            ],
        ]);

        $container->extension('security', [
            'password_hashers' => [
                InMemoryUser::class => 'plaintext',
            ],
            'providers' => [
                'users' => [
                    'memory' => [
                        'users' => [
                            'alice' => ['password' => 'secret', 'roles' => ['ROLE_USER']],
                            'bob' => ['password' => 'secret', 'roles' => ['ROLE_USER']],
                            'admin' => ['password' => 'secret', 'roles' => ['ROLE_USER', 'ROLE_ALLOWED_TO_SWITCH']],
                        ],
                    ],
                ],
            ],
            'firewalls' => [
                'api' => [
                    'pattern' => '^/api',
                    'provider' => 'users',
                    'json_login' => ['check_path' => 'api_login'],
                    'http_basic' => ['realm' => 'test'],
                    'logout' => ['path' => 'api_logout'],
                ],
            ],
            'access_control' => [
                ['path' => '^/api/(login|anon)', 'roles' => 'PUBLIC_ACCESS'],
                ['path' => '^/api', 'roles' => 'ROLE_USER'],
            ],
        ]);

        $apiSession = [
            'firewalls' => ['api'],
            'logout' => ['json_response' => true],
        ];
        if (\in_array($this->environment, ['lifetime', 'revocation', 'agecap'], true)) {
            // Deliberately tiny so the functional tests can wait out
            // expiries in real time.
            $apiSession['token'] = ['lifetime' => 4];
        }
        $container->extension('api_session', $apiSession);

        $services = $container->services();
        $services->set(DenyBobImpersonationListener::class)
            ->tag('kernel.event_listener', ['event' => ImpersonationEnteredEvent::class]);
        $services->set(SwitchUserEventRecorder::class)
            ->tag('kernel.event_listener', ['event' => 'security.switch_user']);
        $services->set(StaleTokenEventRecorder::class)
            ->tag('kernel.event_listener', ['event' => StaleSessionTokenEvent::class]);

        // The revocation reference implementations, each in its own
        // environment so their tiny windows don't disturb other tests.
        if ('revocation' === $this->environment) {
            $services->set(RevokeSupersededTokensListener::class)
                ->tag('kernel.event_listener', ['event' => SessionTokenMintedEvent::class, 'method' => 'onTokenMinted'])
                ->tag('kernel.event_listener', ['event' => VerifySessionTokenEvent::class, 'method' => 'onVerifyToken']);
        }
        if ('agecap' === $this->environment) {
            $services->set(SessionAgeCapListener::class)
                ->tag('kernel.event_listener', ['event' => 'Symfony\Component\Security\Http\Event\LoginSuccessEvent', 'method' => 'onLoginSuccess'])
                ->tag('kernel.event_listener', ['event' => VerifySessionTokenEvent::class, 'method' => 'onVerifyToken']);
        }
        if ('minttrap' === $this->environment) {
            $services->set(UnexpectedTokenMintListener::class)
                ->tag('kernel.event_listener', ['event' => SessionTokenMintedEvent::class]);
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('api_login', '/api/login')->controller(LoginController::class)->methods(['POST']);
        $routes->add('api_logout', '/api/logout')->methods(['POST']);
        $routes->add('api_anon', '/api/anon')->controller('kernel::anon')->methods(['POST']);
        $routes->add('api_whoami', '/api/whoami')->controller('kernel::whoami')->methods(['GET']);
        $routes->add('api_csrf_probe', '/api/csrf-probe')->controller('kernel::csrfProbe')->methods(['POST']);
        $routes->add('plain_csrf_probe', '/csrf-probe')->controller('kernel::csrfProbe')->methods(['POST']);
        $routes->add('api_impersonate', '/api/impersonate')
            ->controller(EnterImpersonationController::class)->methods(['POST']);
        $routes->add('api_impersonate_exit', '/api/impersonate')
            ->controller(ExitImpersonationController::class)->methods(['DELETE']);
        $routes->add('api_refresh', '/api/refresh')
            ->controller(RefreshTokenController::class)->methods(['POST']);
    }

    /**
     * Public endpoint that stores state in the (possibly anonymous)
     * session, mimicking a WebAuthn challenge, and echoes what the
     * session held before - proving whether the session carried over.
     */
    public function anon(Request $request): JsonResponse
    {
        $session = $request->getSession();
        $previous = $session->get('challenge');
        $session->set('challenge', $request->getPayload()->getString('challenge'));

        return new JsonResponse(['previous' => $previous]);
    }

    public function whoami(#[CurrentUser] ?UserInterface $user): JsonResponse
    {
        return new JsonResponse(['user' => $user?->getUserIdentifier()]);
    }

    /**
     * Validates a caller-supplied CSRF token, mimicking a form endpoint.
     * Mounted both inside (/api) and outside the bridged firewall so the
     * bypass can be asserted from both sides.
     */
    public function csrfProbe(Request $request, CsrfTokenManagerInterface $csrfTokenManager): JsonResponse
    {
        $token = new CsrfToken('probe', $request->getPayload()->getString('_token'));

        return new JsonResponse(['valid' => $csrfTokenManager->isTokenValid($token)]);
    }
}
