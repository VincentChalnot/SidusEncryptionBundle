<?php

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Exception\BadNonceException;
use Sidus\EncryptionBundle\Exception\RandomGeneratorException;

/**
 * Base features that should be common to all implementations
 */
abstract class AbstractEncryptionAdapter implements EncryptionAdapterInterface
{
    protected const ENCODING = '8bit';

    /** @var int */
    protected $nonceSize;

    /** @var int */
    protected $keySize;

    /** @var int */
    protected $clearTextBlockSize;

    /** @var int */
    protected $encryptedBlockSize;

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
