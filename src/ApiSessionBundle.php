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

namespace LocksyK\ApiSessionBundle;

use LocksyK\ApiSessionBundle\EventListener\JsonLogoutResponseListener;
use LocksyK\ApiSessionBundle\Security\BridgedFirewallCsrfTokenManager;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\Security\Http\Event\LogoutEvent;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class ApiSessionBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->arrayNode('firewalls')
                    ->info('Names of the firewalls whose session id is carried in the Authorization header.')
                    ->scalarPrototype()->end()
                ->end()
                ->arrayNode('token')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('response_header')
                            ->info('Response header carrying the freshly minted token after login; null to disable.')
                            ->defaultValue('X-Session-Token')
                        ->end()
                        ->scalarNode('prefix')
                            ->info('Prefix of tokens minted by the default HMAC strategy; what keeps them cheaply distinguishable from other bearer schemes.')
                            ->defaultValue('sess_')
                            ->cannotBeEmpty()
                            ->validate()
                                ->ifTrue(static fn ($v): bool => \is_string($v) && str_contains($v, '.'))
                                ->thenInvalid('The token prefix must not contain ".".')
                            ->end()
                        ->end()
                        ->integerNode('lifetime')
                            ->info('Absolute token lifetime in seconds, embedded (signed) in each minted token. Null (default) relies on the session\'s own idle expiry alone; setting a value enables the refresh endpoint.')
                            ->defaultNull()
                        ->end()
                    ->end()
                ->end()
                ->booleanNode('csrf_bypass')
                    ->info('Disable CSRF enforcement on bridged firewalls; bearer-carried sessions have no ambient credential, so classic CSRF does not apply.')
                    ->defaultTrue()
                ->end()
                ->arrayNode('stale_token')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('www_authenticate')
                            ->info('Emit RFC 6750 "WWW-Authenticate: Bearer error=\"invalid_token\"" on 401 responses when a recognised token\'s session no longer exists.')
                            ->defaultTrue()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('logout')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('json_response')
                            ->info('Respond 204 No Content to logout on bridged firewalls instead of Symfony\'s default redirect. App listeners can still replace the response.')
                            ->defaultFalse()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('switch_user')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('role')
                            ->info('Role required to enter impersonation via the switch-user endpoint.')
                            ->defaultValue('ROLE_ALLOWED_TO_SWITCH')
                        ->end()
                        ->enumNode('grant_previous_admin_role')
                            ->info('Append ROLE_PREVIOUS_ADMIN to the impersonation token, as security-http did below 7.0. Must match the installed security-http or the session is deauthenticated on the next request; "auto" reads http-kernel\'s version, which is only wrong if security-http sits on a different major.')
                            ->values(['auto', true, false])
                            ->defaultValue('auto')
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param array{
     *     firewalls: list<string>,
     *     token: array{response_header: string|null, prefix: string, lifetime: int|null},
     *     csrf_bypass: bool,
     *     stale_token: array{www_authenticate: bool},
     *     logout: array{json_response: bool},
     *     switch_user: array{role: string, grant_previous_admin_role: 'auto'|bool},
     * } $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        $container->parameters()
            ->set('api_session.firewalls', $config['firewalls'])
            ->set('api_session.token.response_header', $config['token']['response_header'])
            ->set('api_session.token.prefix', $config['token']['prefix'])
            ->set('api_session.token.lifetime', $config['token']['lifetime'])
            ->set('api_session.csrf_bypass', $config['csrf_bypass'])
            ->set('api_session.stale_token.www_authenticate', $config['stale_token']['www_authenticate'])
            ->set('api_session.logout.json_response', $config['logout']['json_response'])
            ->set('api_session.switch_user.role', $config['switch_user']['role'])
            // "auto" becomes null: the controller decides per request from
            // the running version, so a container built before a Symfony
            // upgrade cannot bake in the wrong answer.
            ->set(
                'api_session.switch_user.grant_previous_admin_role',
                'auto' === $config['switch_user']['grant_previous_admin_role']
                    ? null
                    : $config['switch_user']['grant_previous_admin_role'],
            );

        $services = $container->services();

        if ($config['csrf_bypass']) {
            // Ignore-on-invalid: apps without symfony/security-csrf simply
            // have nothing to bypass.
            $services->set('api_session.csrf_token_manager', BridgedFirewallCsrfTokenManager::class)
                ->decorate('security.csrf.token_manager', null, 0, ContainerInterface::IGNORE_ON_INVALID_REFERENCE)
                ->args([
                    service('.inner'),
                    service('api_session.bridged_firewall_resolver'),
                    service('request_stack'),
                ]);
        }

        if ($config['logout']['json_response']) {
            $services->set('api_session.listener.json_logout_response', JsonLogoutResponseListener::class)
                ->args([service('api_session.bridged_firewall_resolver')])
                ->tag('kernel.event_listener', [
                    'event' => LogoutEvent::class,
                    'priority' => JsonLogoutResponseListener::PRIORITY,
                ]);
        }
    }
}
