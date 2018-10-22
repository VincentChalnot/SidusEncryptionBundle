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

use Sidus\EncryptionBundle\Registry\EncryptionManagerRegistry;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class SidusEncryptionExtension extends Extension
{
    /**
     * {@inheritdoc}
     *
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config/services'));
        $loader->load('encryption.yml');
        $loader->load('event.yml');
        $loader->load('registry.yml');
        $loader->load('security.yml');
        $loader->load('session.yml');
        $loader->load('deprecated.yml'); // Remove me in a future version

        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $registry = $container->getDefinition(EncryptionManagerRegistry::class);
        $registry->replaceArgument(0, $config['preferred_adapter']);
    }
}
