<?php

namespace Sidus\EncryptionBundle\Tests\PHPUnit\Doctrine\Type;

use Doctrine\DBAL\Platforms\MySqlPlatform;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Sidus\EncryptionBundle\Doctrine\Type\EncryptType;
use Sidus\EncryptionBundle\Manager\EncryptionManagerInterface;

class EncryptTypeTest extends TestCase
{
    public function testConvertToPHPValue(): void
    {
        [$type, $encryptionManager] = $this->createType();
        $encryptedString = '\X666';
        $platform = $this->createMock(MySqlPlatform::class);
    
        // The type SHOULD decrypt the encrypted string
        $encryptionManager
            ->expects($this->once())
            ->method('decryptString')
            ->with(base64_decode($encryptedString))
            ->willReturn('my_decrypted_string')
        ;
        
        $value = $type->convertToPHPValue($encryptedString, $platform);
        $this->assertEquals('my_decrypted_string', $value);
    }
    
    public function testConvertToDatabaseValue(): void
    {
        [$type, $encryptionManager] = $this->createType();
        $string = 'my_string';
        $platform = $this->createMock(MySqlPlatform::class);
    
        // The type SHOULD decrypt the encrypted string
        $encryptionManager
            ->expects($this->once())
            ->method('encryptString')
            ->with($string)
            ->willReturn('my_encrypted_string')
        ;
    
        $value = $type->convertToDatabaseValue($string, $platform);
        $this->assertEquals(base64_encode('my_encrypted_string'), $value);
    }
    
    /**
     * @return EncryptType[]|MockObject[]
     */
    private function createType(): array
    {
        $encryptionManager = $this->createMock(EncryptionManagerInterface::class);
        $type = new EncryptType();
        $type->setEncryptionManager($encryptionManager);
    
        return [$type, $encryptionManager];
    }
}
