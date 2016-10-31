<?php

namespace Cyberdean\Security\BotDetectBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files.
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/configuration.html}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('cyb_bot_detect');

        // Here you should define the parameters that are allowed to
        // configure your bundle. See the documentation linked above for
        // more information on that topic.

        //todo add configuation option for : strike UA or simply send 403 (no strike/ban) --> add field type ?

        $rootNode->addDefaultsIfNotSet()->children()
            ->scalarNode('min_ban_interval')->defaultValue('P3D')->info('Minimum PHP DateInterval ban time')->end()
            ->scalarNode('max_ban_interval')->defaultValue('P6M')->info('Maximum PHP DateInterval ban time')->end()
            ->integerNode('ip_banned_response_code')->defaultValue(403)->treatNullLike(403)->info('HTTP code when user ip is banned')->end()

            ->arrayNode('err404')->children()
                ->booleanNode('check')->defaultFalse()->info('If true strike 404 errors')->end()
            ->end()
            ->end()

            ->arrayNode('err4xx')->children()
                ->booleanNode('check')->defaultTrue()->info('If true strike 4xx errors (not 404)')->end()
            ->end()
            ->end()

            ->arrayNode('ua')->children()
                ->booleanNode('check')->defaultTrue()->info('If true strike ua bad bot')->end()
            ->end()
            ->end()
        ->end()
        ->end();

        return $treeBuilder;
    }
}
