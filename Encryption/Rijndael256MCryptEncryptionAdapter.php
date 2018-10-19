<?php /** @noinspection CryptographicallySecureAlgorithmsInspection */

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Exception\EncryptionException;

/**
 * Mcrypt implementation of Rijndael-256, NOT AES-256!
 * http://php.net/manual/en/function.mcrypt-encrypt.php#117667
 */
class Rijndael256MCryptEncryptionAdapter extends AbstractEncryptionAdapter
{
    /**
     * All size parameters are deducted from cypher mode
     */
    public function __construct()
    {
        if (!\function_exists('mcrypt_encrypt')) {
            throw new EncryptionException('Mcrypt extension is not installed');
        }
        $this->keySize = mcrypt_get_key_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC); // 32
        $this->nonceSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC); // 32
        $this->clearTextBlockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC); // 32
        $this->encryptedBlockSize = $this->clearTextBlockSize;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $clearTextMessage, string $nonce, string $key): string
    {
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_256,
            $key,
            $clearTextMessage,
            MCRYPT_MODE_CBC,
            $nonce
        );
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $encryptedMessage, string $nonce, string $key): string
    {
        return mcrypt_decrypt(
            MCRYPT_RIJNDAEL_256,
            $key,
            $encryptedMessage,
            MCRYPT_MODE_CBC,
            $nonce
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encryptCipherKey(string $clearTextMessage, string $key): string
    {
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_256,
            $key,
            $clearTextMessage,
            MCRYPT_MODE_ECB
        );
    }

    /**
     * {@inheritdoc}
     */
    public function decryptCipherKey(string $encryptedMessage, string $key): string
    {
        return mcrypt_decrypt(
            MCRYPT_RIJNDAEL_256,
            $key,
            $encryptedMessage,
            MCRYPT_MODE_ECB
        );
    }
}
