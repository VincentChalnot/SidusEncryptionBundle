<?php

namespace Sidus\EncryptionBundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\StringType;
use Sidus\EncryptionBundle\Manager\EncryptionManagerInterface;

class EncryptType extends StringType implements EncryptTypeInterface
{
    private EncryptionManagerInterface $encryptionManager;

    public function convertToPHPValue($value, AbstractPlatform $platform)
    {
        $value = base64_decode($value);
        
        return $this->encryptionManager->decryptString($value);
    }

    public function convertToDatabaseValue($value, AbstractPlatform $platform)
    {
        $value =  $this->encryptionManager->encryptString($value);
        
        return base64_encode($value);
    }

    public function setEncryptionManager(EncryptionManagerInterface $encryptionManager): void
    {
        $this->encryptionManager = $encryptionManager;
    }

    public function getName()
    {
        return 'encrypt_string';
    }
}
