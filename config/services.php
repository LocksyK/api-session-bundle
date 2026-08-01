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

use LocksyK\ApiSessionBundle\Controller\EnterImpersonationController;
use LocksyK\ApiSessionBundle\Controller\ExitImpersonationController;
use LocksyK\ApiSessionBundle\Controller\LoginController;
use LocksyK\ApiSessionBundle\Controller\RefreshTokenController;
use LocksyK\ApiSessionBundle\EventListener\BearerSessionRequestListener;
use LocksyK\ApiSessionBundle\EventListener\BearerSessionResponseListener;
use LocksyK\ApiSessionBundle\EventListener\StaleTokenExceptionListener;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallResolver;
use LocksyK\ApiSessionBundle\Security\StaleTokenDetector;
use LocksyK\ApiSessionBundle\Token\HmacTokenStrategy;
use LocksyK\ApiSessionBundle\Token\SessionTokenIssuer;
use LocksyK\ApiSessionBundle\Token\TokenStrategyInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Core\User\UserProviderInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services->set('api_session.token_strategy.hmac', HmacTokenStrategy::class)
        ->args([
            param('kernel.secret'),
            param('api_session.token.prefix'),
        ]);

    // Apps swap the token strategy by re-aliasing the interface.
    $services->alias(TokenStrategyInterface::class, 'api_session.token_strategy.hmac');

    // The single mint pipeline (lifetime + minted event); also the
    // service for apps issuing tokens from their own endpoints.
    $services->set('api_session.token_issuer', SessionTokenIssuer::class)
        ->args([
            service(TokenStrategyInterface::class),
            service('event_dispatcher'),
            param('api_session.token.lifetime'),
        ]);
    $services->alias(SessionTokenIssuer::class, 'api_session.token_issuer');

    $services->set('api_session.bridged_firewall_resolver', BridgedFirewallResolver::class)
        ->args([
            service('security.helper'),
            param('api_session.firewalls'),
        ]);

    $services->set('api_session.stale_token_detector', StaleTokenDetector::class)
        ->args([service('event_dispatcher')]);

    $services->set('api_session.listener.bearer_session_request', BearerSessionRequestListener::class)
        ->args([
            service('api_session.bridged_firewall_resolver'),
            service(TokenStrategyInterface::class),
            service('api_session.stale_token_detector'),
            service('event_dispatcher'),
        ])
        ->tag('kernel.event_subscriber');

    $services->set('api_session.listener.stale_token_exception', StaleTokenExceptionListener::class)
        ->args([
            service('api_session.bridged_firewall_resolver'),
            service('api_session.stale_token_detector'),
        ])
        ->tag('kernel.event_subscriber');

    $services->set('api_session.listener.bearer_session_response', BearerSessionResponseListener::class)
        ->args([
            service('api_session.bridged_firewall_resolver'),
            service('api_session.token_issuer'),
            service('api_session.stale_token_detector'),
            service('security.token_storage'),
            param('api_session.token.response_header'),
            param('api_session.stale_token.www_authenticate'),
        ])
        ->tag('kernel.event_subscriber');

    // Opt-in login responder: mount on the firewall's json_login
    // check_path; the authenticator handles credentials, this shapes the
    // success response (user, roles, token in the body).
    $services->set(LoginController::class)
        ->args([
            service('security.token_storage'),
            service('api_session.bridged_firewall_resolver'),
            service('api_session.token_issuer'),
        ])
        ->tag('controller.service_arguments');

    // Refresh endpoint - app-mounted like the impersonation controllers;
    // functional only when token.lifetime is configured.
    $services->set(RefreshTokenController::class)
        ->args([
            service('api_session.bridged_firewall_resolver'),
            service('api_session.stale_token_detector'),
            service('api_session.token_issuer'),
            param('api_session.token.response_header'),
        ])
        ->tag('controller.service_arguments');

    // Impersonation endpoints - the bundle registers NO routes for these;
    // the app opts in by declaring routes that point at the class names.
    $services->set(EnterImpersonationController::class)
        ->args([
            service('security.token_storage'),
            service('security.authorization_checker'),
            service('event_dispatcher'),
            service('api_session.bridged_firewall_resolver'),
            // Alias exists when the app has exactly one user provider;
            // multi-provider apps rebind this argument.
            service(UserProviderInterface::class)->nullOnInvalid(),
            param('api_session.switch_user.role'),
            param('api_session.switch_user.grant_previous_admin_role'),
        ])
        ->tag('controller.service_arguments');

    $services->set(ExitImpersonationController::class)
        ->args([
            service('security.token_storage'),
            service('event_dispatcher'),
            service('api_session.bridged_firewall_resolver'),
        ])
        ->tag('controller.service_arguments');
};
