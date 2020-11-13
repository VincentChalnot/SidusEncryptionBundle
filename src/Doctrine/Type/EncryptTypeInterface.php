<?php

namespace Sidus\EncryptionBundle\Doctrine\Type;

use Sidus\EncryptionBundle\Manager\EncryptionManagerInterface;

interface EncryptTypeInterface
{
    public function setEncryptionManager(EncryptionManagerInterface $encryptionManager): void;
}
