<?php

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Exception\EncryptionException;
use const Sodium\CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;

/**
 * Sodium implementation of XChaChaPoly1305 encryption scheme, IETF version
 */
class XChaChaPolySodiumEncryptionAdapter extends AbstractEncryptionAdapter
{
    /**
     * @param int $blockSize
     */
    public function __construct(int $blockSize = 4096)
    {
        if (!\function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            throw new EncryptionException('Sodium extension is not installed');
        }
        $this->keySize = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES; // 32
        $this->nonceSize = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24
        $this->clearTextBlockSize = $blockSize;
        $this->encryptedBlockSize = $blockSize + CRYPTO_AEAD_CHACHA20POLY1305_ABYTES; // 128-bit authentication tag
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $clearTextMessage, string $nonce, string $key): string
    {
        try {
            return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
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
        $decryptedMessage = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
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
