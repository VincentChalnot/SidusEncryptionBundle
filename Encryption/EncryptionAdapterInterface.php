<?php

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Exception\BadNonceException;
use Sidus\EncryptionBundle\Exception\EncryptionException;
use Sidus\EncryptionBundle\Exception\RandomGeneratorException;

/**
 * Common methods needed for any encryption adapter
 */
interface EncryptionAdapterInterface
{
    /**
     * @param string $clearTextMessage
     * @param string $nonce
     * @param string $key
     *
     * @throws EncryptionException
     *
     * @return string
     */
    public function encrypt(string $clearTextMessage, string $nonce, string $key): string;

    /**
     * @param string $encryptedMessage
     * @param string $nonce
     * @param string $key
     *
     * @throws EncryptionException
     *
     * @return string
     */
    public function decrypt(string $encryptedMessage, string $nonce, string $key): string;

    /**
     * @throws RandomGeneratorException
     *
     * @return string
     */
    public function generateNonce(): string;

    /**
     * @throws RandomGeneratorException
     *
     * @return string
     */
    public function generateKey(): string;

    /**
     * @param string $message
     *
     * @throws BadNonceException
     *
     * @return string
     */
    public function parseNonce(string &$message): string;

    /**
     * @return int
     */
    public function getKeySize(): int;

    /**
     * @return int
     */
    public function getClearTextBlockSize(): int;
    /**
     * @return int
     */
    public function getEncryptedBlockSize(): int;

    /**
     * @return int
     */
    public function getNonceSize(): int;
}
