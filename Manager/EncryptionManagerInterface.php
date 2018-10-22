<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\Manager;

use Sidus\EncryptionBundle\Encryption\EncryptionAdapterInterface;
use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;

/**
 * The encryption manager will handle the encryption/decryption of cipher key and data in the whole application
 * The cipher key is encrypted in the user with it's password (clear-text password) which means the cipher key can only
 * be retrieved at user's login. That's why it is passed along in the session (in clear form) This way the cipher-key is
 * never stored on the server (except in PHP's sessions) which means that the data are safe if the database or the
 * files are stolen. For improved security you can lower PHP's session duration.
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
interface EncryptionManagerInterface
{
    /**
     * Can be used for low-level function access
     *
     * @return EncryptionAdapterInterface
     */
    public function getEncryptionAdapter(): EncryptionAdapterInterface;

    /**
     * Decrypt the cipher key used to encrypt/decrypt data using the user's password and saves it in the session
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     */
    public function decryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void;

    /**
     * Encrypt enterprise cipher key for a user
     * Used at user creation and password change
     * You need to persist the user after that
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     */
    public function encryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void;

    /**
     * Create a new cipher key for a user
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     *
     * @throws EmptyCipherKeyException
     */
    public function createCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void;

    /**
     * Encrypt a string and automatically generate the nonce if needed
     *
     * @param string $string
     * @param string $nonce
     *
     * @throws EmptyCipherKeyException
     *
     * @return string
     */
    public function encryptString(string $string, string $nonce = null): string;

    /**
     * Decrypt an encrypted string, try to parse the nonce if not specified
     * Absolutely NOT safe for binary data
     *
     * @param string $encryptedString
     * @param string $nonce
     *
     * @throws EmptyCipherKeyException
     *
     * @return string
     */
    public function decryptString(string $encryptedString, string $nonce = null): string;

    /**
     * Encrypt a block of data from the input stream
     *
     * @param resource $inputStream
     * @param string   $nonce
     *
     * @throws EmptyCipherKeyException
     *
     * @return string
     */
    public function encryptStreamBlock($inputStream, string $nonce): string;

    /**
     * Decrypt a block of the input stream
     *
     * @param resource $inputStream
     * @param string   $nonce
     *
     * @throws EmptyCipherKeyException
     *
     * @return string
     */
    public function decryptStreamBlock($inputStream, string $nonce): string;

    /**
     * Encrypt a whole file by streaming each block from the input file to the output
     *
     * @param string $inputFilePath
     * @param string $outputFilePath
     *
     * @throws EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function encryptFile(string $inputFilePath, string $outputFilePath): void;

    /**
     * @param resource $inputStream
     * @param resource $outputStream
     *
     * @throws EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function encryptStream($inputStream, $outputStream): void;

    /**
     * Decrypt a file by streaming each block from the input to the output
     *
     * @param string $inputFilePath
     * @param string $outputFilePath
     * @param int    $fileSize
     *
     * @throws EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function decryptFile(string $inputFilePath, string $outputFilePath, int $fileSize = null): void;

    /**
     * Decrypt a stream
     * You can specify the original unencrypted file size in order to cut the output at the exact same location
     *
     * @param resource $inputStream
     * @param resource $outputStream
     * @param int      $fileSize
     *
     * @throws EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function decryptStream($inputStream, $outputStream, int $fileSize = null): void;
}
