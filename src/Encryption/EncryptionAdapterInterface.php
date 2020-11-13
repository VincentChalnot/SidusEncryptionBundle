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
use Sidus\EncryptionBundle\Exception\EncryptionException;
use Sidus\EncryptionBundle\Exception\RandomGeneratorException;

/**
 * Common methods needed for any encryption adapter
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
interface EncryptionAdapterInterface
{
    /**
     * By convention: {library}.{code}
     *
     * @return string
     */
    public static function getCode(): string;

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
     * This method is necessary for back-compatibility but will be removed in future versions
     *
     * @param string $cipherKey
     * @param string $key
     *
     * @throws EncryptionException
     *
     * @return string
     */
    public function encryptCipherKey(string $cipherKey, string $key): string;

    /**
     * This method is necessary for back-compatibility but will be removed in future versions
     *
     * @param string $encryptedCipherKey
     * @param string $key
     *
     * @throws EncryptionException
     *
     * @return string
     */
    public function decryptCipherKey(string $encryptedCipherKey, string $key): string;

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
