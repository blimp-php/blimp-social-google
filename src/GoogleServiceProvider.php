<?php
namespace Blimp\Accounts;

use Pimple\ServiceProviderInterface;
use Pimple\Container;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Blimp\Accounts\GrantTypes\Google;

class GoogleServiceProvider implements ServiceProviderInterface {
    public function register(Container $api) {
        $api->extend('blimp.extend', function ($status, $api) {
            if($status) {
                $api['security.oauth.grant.urn:blimp:accounts:google'] = function() {
                    return new Google();
                };

                if($api->offsetExists('config.root')) {
                    $api->extend('config.root', function ($root, $api) {
                        $tb = new TreeBuilder();

                        $rootNode = $tb->root('google');

                        $rootNode
                            ->children()
                                ->scalarNode('client_id')->cannotBeEmpty()->end()
                                ->scalarNode('client_secret')->cannotBeEmpty()->end()
                                ->scalarNode('scope')->defaultValue('email https://www.googleapis.com/auth/plus.login')->end()
                                ->scalarNode('fields')->defaultValue('id,name,link,gender,email,picture')->end()
                            ->end()
                        ;

                        $root->append($rootNode);

                        return $root;
                    });
                }
            }

            return $status;
        });
    }
}
