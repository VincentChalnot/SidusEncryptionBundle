<?php
/*
 * This file is part of the Sidus/BaseBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\DependencyInjection\Compiler;

use Sidus\EncryptionBundle\Encryption\EncryptionAdapterInterface;
use Sidus\EncryptionBundle\Manager\EncryptionManager;
use Sidus\EncryptionBundle\Registry\EncryptionManagerRegistry;
use Sidus\EncryptionBundle\Session\CipherKeyStorageInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Find inject services implementing EncryptionAdapterInterface into EncryptionManagers and into registry
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EncryptionAdapterCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->has(EncryptionManagerRegistry::class)) {
            return;
        }

        foreach ($container->findTaggedServiceIds('sidus.encryption.adapter') as $adapterId => $tags) {
            $adapterDefinition = $container->getDefinition($adapterId);
            $class = $adapterDefinition->getClass();
            /** @var EncryptionAdapterInterface $class */
            $managerDefinition = new Definition(
                EncryptionManager::class,
                [
                    new Reference($adapterId),
                    new Reference(CipherKeyStorageInterface::class),
                    $container->getParameter('sidus.encryption.throw_exceptions'),
                ]
            );
            $managerDefinition->addTag('sidus.encryption.manager');
            $managerId = 'sidus.encryption.manager.'.$class;
            $container->setDefinition($managerId, $managerDefinition);
        }
    }
}
