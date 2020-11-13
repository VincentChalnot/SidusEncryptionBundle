<?php

namespace Sidus\EncryptionBundle\Tests\PHPUnit\Adapter;

use PHPUnit\Framework\TestCase;
use Sidus\EncryptionBundle\Encryption\Aes256GcmSodiumEncryptionAdapter;
use Sidus\EncryptionBundle\Encryption\EncryptionAdapterInterface;

class Aes256GcmSodiumEncryptionAdapterTest extends TestCase
{
    /**
     * @dataProvider getDataProvider
     */
    public function testEncryptAndDecrypt(string $originalString): void
    {
        $adapter = $this->createAdapter();
    
        $nonce = $adapter->generateNonce();
        $key = $adapter->generateKey();
    
        $encryptedString = $adapter->encrypt($originalString, $nonce, $key);
        $decryptedString = $adapter->decrypt($encryptedString, $nonce, $key);
        
        $this->assertEquals($originalString, $decryptedString);
    }
    
    public function getDataProvider(): array
    {
        return [
            ['test'],
            ['very long string MsdfkozoeP ... ESfDSPE $$ŜDCX/s> /sF^SEFD \TERIOFKD \\/fsd/EPKFDSKQZLJEF$É44324234sd%sDCÙ'],
            ['%%%%%%%TEST%%%%%%%'],
            ['_'],
            ['@/%ù*µ$£êêê$$=+={{}#~&'],
            [bin2hex(random_bytes(1))],
            [bin2hex(random_bytes(100))],
            [bin2hex(random_bytes(400))],
            [bin2hex(random_bytes(1000))],
            [bin2hex(random_bytes(10000))],
        ];
    }
    
    private function createAdapter(): EncryptionAdapterInterface
    {
        return new Aes256GcmSodiumEncryptionAdapter();
    }
}
