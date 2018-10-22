<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle;

use Sidus\EncryptionBundle\DependencyInjection\Compiler\EncryptionAdapterCompilerPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * The EncryptionBundle allows you to store encrypted files and data in Doctrine's entity in a very simple way
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 * @author Corentin Bouix <cbouix@clever-age.com>
 */
class SidusEncryptionBundle extends Bundle
{
    /**
     * @param ContainerBuilder $container
     */
    public function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new EncryptionAdapterCompilerPass());
    }
}
