<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Exception\EncryptionException;

/**
 * Sodium implementation of XChaChaPoly1305 encryption scheme, IETF version
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
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
        $this->encryptedBlockSize = $blockSize + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES; // 128-bit authentication tag
    }

    /**
     * {@inheritdoc}
     */
    public static function getCode(): string
    {
        return 'sodium.xchacha20-poly1305-ietf';
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $clearTextMessage, string $nonce, string $key): string
    {
        $encryptedMessage = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $clearTextMessage,
            $nonce,
            $nonce,
            $key
        );
        if (false === $encryptedMessage) {
            throw new EncryptionException('Unable to encrypt message');
        }

        return $encryptedMessage;
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
