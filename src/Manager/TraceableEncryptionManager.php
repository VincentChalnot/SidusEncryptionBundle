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
use Sidus\EncryptionBundle\Session\CipherKeyStorageInterface;
use Symfony\Component\Stopwatch\Stopwatch;

/**
 * @author Vincent Chalnot <vincent@sidus.fr>
 * @author Corentin Bouix <cbouix@clever-age.com>
 */
class TraceableEncryptionManager extends EncryptionManager
{
    protected Stopwatch $stopwatch;

    public function __construct(
        EncryptionAdapterInterface $encryptionAdapter,
        CipherKeyStorageInterface $cipherKeyStorage,
        bool $throwExceptions,
        Stopwatch $stopwatch
    ) {
        parent::__construct($encryptionAdapter, $cipherKeyStorage, $throwExceptions);
        $this->stopwatch = $stopwatch;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        $this->startWatch(__METHOD__);
        parent::decryptCipherKey($user, $plainTextPassword);
        $this->stopWatch(__METHOD__);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        $this->startWatch(__METHOD__);
        parent::encryptCipherKey($user, $plainTextPassword);
        $this->stopWatch(__METHOD__);
    }

    /**
     * {@inheritdoc}
     */
    public function createCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        $this->startWatch(__METHOD__);
        parent::createCipherKey($user, $plainTextPassword);
        $this->stopWatch(__METHOD__);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptString(string $string, string $nonce = null): string
    {
        $this->startWatch(__METHOD__);
        $string = parent::encryptString($string, $nonce);
        $this->stopWatch(__METHOD__);
    
        return $string;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptString(string $encryptedString, string $nonce = null): string
    {
        $this->startWatch(__METHOD__);
        $string = parent::decryptString($encryptedString, $nonce);
        $this->stopWatch(__METHOD__);
    
        return $string;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptStreamBlock($inputStream, string $nonce): string
    {
        $this->startWatch(__METHOD__);
        $string = parent::encryptStreamBlock($inputStream, $nonce);
        $this->stopWatch(__METHOD__);
    
        return $string;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptStreamBlock($inputStream, string $nonce): string
    {
        $this->startWatch(__METHOD__);
        $string =  parent::decryptStreamBlock($inputStream, $nonce);
        $this->stopWatch(__METHOD__);
    
        return $string;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptFile(string $inputFilePath, string $outputFilePath): void
    {
        $this->startWatch(__METHOD__);
        parent::encryptFile($inputFilePath, $outputFilePath);
        $this->stopWatch(__METHOD__);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptFile(string $inputFilePath, string $outputFilePath, int $fileSize = null): void
    {
        $this->startWatch(__METHOD__);
        parent::decryptFile($inputFilePath, $outputFilePath, $fileSize);
        $this->stopWatch(__METHOD__);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptStream($inputStream, $outputStream): void
    {
        $this->startWatch(__METHOD__);
        parent::encryptStream($inputStream, $outputStream);
        $this->stopWatch(__METHOD__);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptStream($inputStream, $outputStream, int $fileSize = null): void
    {
        $this->startWatch(__METHOD__);
        parent::decryptStream($inputStream, $outputStream, $fileSize);
        $this->stopWatch(__METHOD__);
    }

    protected function startWatch(string $name, string $category = null): void
    {
        if ($this->stopwatch) {
            $this->stopwatch->start($name, $category);
        }
    }

    protected function stopWatch(string $name): void
    {
        if ($this->stopwatch) {
            $this->stopwatch->stop($name);
        }
    }
}
