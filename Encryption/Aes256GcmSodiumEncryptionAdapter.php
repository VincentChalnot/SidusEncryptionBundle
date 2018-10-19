<?php

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Exception\EncryptionException;

/**
 * Sodium implementation of AES-256-GCM encryption scheme, ONLY ON SUPPORTED HARDWARE
 */
class Aes256GcmSodiumEncryptionAdapter extends AbstractEncryptionAdapter
{
    /**
     * @param int $blockSize
     */
    public function __construct(int $blockSize = 4096)
    {
        if (!\function_exists('sodium_crypto_aead_aes256gcm_is_available')) {
            throw new EncryptionException('Sodium extension is not installed');
        }
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            throw new EncryptionException('AES-256-GCM is not available on your hardware');
        }
        $this->keySize = SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES;
        $this->nonceSize = SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;
        $this->clearTextBlockSize = $blockSize;
        $this->encryptedBlockSize = $blockSize + SODIUM_CRYPTO_AEAD_AES256GCM_ABYTES;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $clearTextMessage, string $nonce, string $key): string
    {
        try {
            return sodium_crypto_aead_aes256gcm_encrypt(
                $clearTextMessage,
                $nonce,
                $nonce,
                $key
            );
        } catch (\SodiumException $e) {
            throw new EncryptionException('Unable to encrypt message', 0, $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $encryptedMessage, string $nonce, string $key): string
    {
        $decryptedMessage = sodium_crypto_aead_aes256gcm_decrypt(
            $encryptedMessage,
            $nonce,
            $nonce,
            $key
        );
        if (!\is_string($decryptedMessage)) {
            throw new EncryptionException('Invalid message');
        }

        return $decryptedMessage;
    }
}
