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

use Exception;
use Sidus\EncryptionBundle\Encryption\EncryptionAdapterInterface;
use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;
use Sidus\EncryptionBundle\Exception\EncryptionException;
use Sidus\EncryptionBundle\Exception\FileHandlingException;
use Sidus\EncryptionBundle\Session\CipherKeyStorageInterface;

/**
 * {@inheritdoc}
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 * @author Corentin Bouix <cbouix@clever-age.com>
 */
class EncryptionManager implements EncryptionManagerInterface
{
    protected EncryptionAdapterInterface $encryptionAdapter;
    protected CipherKeyStorageInterface $cipherKeyStorage;
    protected bool $throwExceptions;
    
    public function __construct(
        EncryptionAdapterInterface $encryptionAdapter,
        CipherKeyStorageInterface $cipherKeyStorage,
        bool $throwExceptions = true
    ) {
        $this->encryptionAdapter = $encryptionAdapter;
        $this->cipherKeyStorage = $cipherKeyStorage;
        $this->throwExceptions = $throwExceptions;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptionAdapter(): EncryptionAdapterInterface
    {
        return $this->encryptionAdapter;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptCipherKey(UserEncryptionProviderInterface $user, string $plainTextPassword): void
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        $encryptedCipherKey = $user->getEncryptedCipherKey();
        if (!$encryptedCipherKey) {
            throw new EmptyCipherKeyException('Empty encrypted cipher key');
        }
        $cipherKey = $this->encryptionAdapter->decryptCipherKey(
            $encryptedCipherKey,
            md5((string) $plainTextPassword)
        );
        $this->cipherKeyStorage->setCipherKey($cipherKey);
        $this->cipherKeyStorage->setEncryptionOwnershipId($user->getEncryptionOwnershipId());
    }

    /**
     * {@inheritdoc}
     */
    public function encryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        $encrypted = $this->encryptionAdapter->encryptCipherKey(
            $this->cipherKeyStorage->getCipherKey(),
            md5((string) $plainTextPassword)
        );

        $user->setEncryptedCipherKey($encrypted);
    }

    /**
     * {@inheritdoc}
     */
    public function createCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        $this->cipherKeyStorage->setCipherKey($this->encryptionAdapter->generateKey());
        $this->encryptCipherKey($user, $plainTextPassword);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptString(string $string, string $nonce = null): string
    {
        if (null === $nonce) {
            $nonce = $this->encryptionAdapter->generateNonce();
        }
    
        try {
            $encrypted = $this->encryptionAdapter->encrypt($string, $nonce, $this->cipherKeyStorage->getCipherKey());
        } catch (Exception $exception) {
            if ($this->throwExceptions) {
                throw $exception;
            }
    
            return '';
        }

        return $nonce.$encrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptString(string $encryptedString, string $nonce = null): string
    {
        if ($nonce === null) {
            $nonce = $this->encryptionAdapter->parseNonce($encryptedString);
        }
    
        try {
            $decrypted = $this->encryptionAdapter->decrypt(
                $encryptedString,
                $nonce,
                $this->cipherKeyStorage->getCipherKey()
            );
        } catch (Exception $exception) {
            if ($this->throwExceptions) {
                throw $exception;
            }
    
            return '';
        }

        return rtrim($decrypted, "\0");
    }

    /**
     * {@inheritdoc}
     */
    public function encryptStreamBlock($inputStream, string $nonce): string
    {
        $block = fread($inputStream, $this->encryptionAdapter->getClearTextBlockSize());
        if (false === $block) {
            throw new EncryptionException('Unable to read from clear-text stream');
        }

        return $this->encryptionAdapter->encrypt($block, $nonce, $this->cipherKeyStorage->getCipherKey());
    }

    /**
     * {@inheritdoc}
     */
    public function decryptStreamBlock($inputStream, string $nonce): string
    {
        $encryptedBlock = fread($inputStream, $this->encryptionAdapter->getEncryptedBlockSize());
        if (false === $encryptedBlock) {
            throw new EncryptionException('Unable to read from encrypted stream');
        }

        return $this->encryptionAdapter->decrypt($encryptedBlock, $nonce, $this->cipherKeyStorage->getCipherKey());
    }

    /**
     * {@inheritdoc}
     */
    public function encryptFile(string $inputFilePath, string $outputFilePath): void
    {
        $inputStream = fopen($inputFilePath, 'rb');
        
        if (!$inputStream) {
            throw new FileHandlingException("Unable to open file '{$inputFilePath}' in read mode (binary)");
        }

        $outputStream = fopen($outputFilePath, 'wb');
        if (!$outputStream) {
            throw new FileHandlingException("Unable to open file '{$outputFilePath}' in write mode (binary)");
        }

        $this->encryptStream($inputStream, $outputStream);

        if (!fclose($inputStream)) {
            throw new FileHandlingException("Unable to close stream for file {$inputFilePath}");
        }
        
        if (!fclose($outputStream)) {
            throw new FileHandlingException("Unable to close stream for file {$outputStream}");
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decryptFile(string $inputFilePath, string $outputFilePath, int $fileSize = null): void
    {
        $inputStream = fopen($inputFilePath, 'rb');
        
        if (!$inputStream) {
            throw new FileHandlingException("Unable to open file '{$inputFilePath}' in read mode (binary)");
        }

        $outputStream = fopen($outputFilePath, 'wb');
        if (!$outputStream) {
            throw new FileHandlingException("Unable to open file '{$outputFilePath}' in write mode (binary)");
        }

        $this->decryptStream($inputStream, $outputStream, $fileSize);

        if (!fclose($inputStream)) {
            throw new FileHandlingException("Unable to close stream for file {$inputFilePath}");
        }
        if (!fclose($outputStream)) {
            throw new FileHandlingException("Unable to close stream for file {$outputStream}");
        }
    }

    /**
     * {@inheritdoc}
     */
    public function encryptStream($inputStream, $outputStream): void
    {
        $nonce = $this->encryptionAdapter->generateNonce();
        if (false === fwrite($outputStream, $nonce)) {
            throw new FileHandlingException('Unable to write to output stream');
        }

        while (!feof($inputStream)) {
            $encryptedBlock = $this->encryptStreamBlock($inputStream, $nonce);
            if (false === fwrite($outputStream, $encryptedBlock)) {
                throw new FileHandlingException('Unable to write to output stream');
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decryptStream($inputStream, $outputStream, int $fileSize = null): void
    {
        $nonce = fread($inputStream, $this->encryptionAdapter->getNonceSize());

        if (false === $nonce) {
            throw new FileHandlingException('Unable to read nounce from input stream');
        }

        $outputLength = $fileSize;
        while (!feof($inputStream)) {
            if (null === $outputLength) {
                $writeSucceeded = fwrite($outputStream, $this->decryptStreamBlock($inputStream, $nonce));
            } else {
                $writeSucceeded = fwrite($outputStream, $this->decryptStreamBlock($inputStream, $nonce), $outputLength);
                if ($fileSize) {
                    $outputLength -= $this->encryptionAdapter->getClearTextBlockSize();
                }
            }
            if (false === $writeSucceeded) {
                throw new FileHandlingException('Unable to write to output stream');
            }
        }
    }
}
