<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link
 * http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class Configuration implements ConfigurationInterface
{
    protected $root;

    /**
     * @param string $root
     */
    public function __construct($root = 'sidus_encryption')
    {
        $this->root = $root;
    }

    /**
     * {@inheritdoc}
     * @throws \RuntimeException
     * @throws \InvalidArgumentException
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root($this->root);

        $rootNode
            ->children()
            ->scalarNode('preferred_adapter')->isRequired()->end()
            ->end();

        return $treeBuilder;
    }
}
