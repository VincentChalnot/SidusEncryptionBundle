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

use Sidus\EncryptionBundle\Exception\BadNonceException;
use Sidus\EncryptionBundle\Exception\RandomGeneratorException;

/**
 * Base features that should be common to all implementations
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
abstract class AbstractEncryptionAdapter implements EncryptionAdapterInterface
{
    protected const ENCODING = '8bit';

    protected int $nonceSize;
    protected int $keySize;
    protected int $clearTextBlockSize;
    protected int $encryptedBlockSize;

    /**
     * {@inheritdoc}
     */
    public function encryptCipherKey(string $cipherKey, string $key): string
    {
        $nonce = $this->generateNonce();

        return $nonce.$this->encrypt($cipherKey, $nonce, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptCipherKey(string $encryptedCipherKey, string $key): string
    {
        $nonce = $this->parseNonce($encryptedCipherKey);

        return $this->decrypt($encryptedCipherKey, $nonce, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function generateNonce(): string
    {
        return $this->generateRandomBytes($this->getNonceSize());
    }

    /**
     * {@inheritdoc}
     */
    public function generateKey(): string
    {
        return $this->generateRandomBytes($this->getKeySize());
    }

    /**
     * {@inheritdoc}
     */
    public function parseNonce(string &$message): string
    {
        if (mb_strlen($message, static::ENCODING) < $this->getNonceSize()) {
            throw new BadNonceException('Unable to parse nounce from message');
        }
        $nonce = mb_substr($message, 0, $this->getNonceSize(), static::ENCODING);
        $message = mb_substr($message, $this->getNonceSize(), null, static::ENCODING);

        return $nonce;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeySize(): int
    {
        return $this->keySize;
    }

    /**
     * {@inheritdoc}
     */
    public function getClearTextBlockSize(): int
    {
        return $this->clearTextBlockSize;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptedBlockSize(): int
    {
        return $this->encryptedBlockSize;
    }

    /**
     * {@inheritdoc}
     */
    public function getNonceSize(): int
    {
        return $this->nonceSize;
    }

    /**
     * Generate cryptographically random bytes
     *
     * @param int $size
     *
     * @return string
     */
    protected function generateRandomBytes(int $size): string
    {
        try {
            return random_bytes($size);
        } catch (\Exception $e) {
            throw new RandomGeneratorException('Unable to generate random bytes', 0, $e);
        }
    }
}
