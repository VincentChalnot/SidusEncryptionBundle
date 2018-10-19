<?php

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;
use Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException;
use Sidus\EncryptionBundle\Exception\EncryptionException;
use Sidus\EncryptionBundle\Exception\FileHandlingException;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Stopwatch\Stopwatch;

/**
 * {@inheritdoc}
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EncryptionManager implements EncryptionManagerInterface
{
    protected const SESSION_CIPHER_KEY = 'sidus.encryption.cipherkey';
    protected const SESSION_OWNERSHIP_KEY = 'sidus.encryption.ownership';

    /** @var EncryptionAdapterInterface */
    protected $encryptionAdapter;

    /** @var Session */
    protected $session;

    /** @var Stopwatch|null */
    protected $stopwatch;

    /** @var string */
    protected $cipherKey;

    /** @var mixed */
    protected $encryptionOwnershipId;

    /**
     * Doctrine is only used when $autogenerateKey is set to true
     *
     * @param EncryptionAdapterInterface $encryptionAdapter
     * @param Session                    $session
     * @param Stopwatch|null             $stopwatch
     */
    public function __construct(
        EncryptionAdapterInterface $encryptionAdapter,
        Session $session,
        Stopwatch $stopwatch = null
    ) {
        $this->encryptionAdapter = $encryptionAdapter;
        $this->session = $session;
        $this->stopwatch = $stopwatch;
    }

    /**
     * Decrypt the cipher key used to encrypt/decrypt data using the user's password and saves it in the session
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     */
    public function decryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        $encryptedCipherKey = $user->getEncryptedCipherKey();
        if (!$encryptedCipherKey) {
            throw new EmptyCipherKeyException('Empty encrypted cipher key');
        }
        $nonce = $this->encryptionAdapter->parseNonce($encryptedCipherKey);
        $cipherKey = $this->encryptionAdapter->decrypt($encryptedCipherKey, $nonce, md5((string) $plainTextPassword));
        $this->setCipherKey($cipherKey);
        $this->setEncryptionOwnershipId($user->getEncryptionOwnershipId());
    }

    /**
     * Encrypt enterprise cipher key for a user
     * Used at user creation and password change
     * You need to persist the user after that
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     */
    public function encryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        $nonce = $this->encryptionAdapter->generateNonce();
        $encrypted = $this->encryptionAdapter->encrypt($this->getCipherKey(), $nonce, md5((string) $plainTextPassword));

        $user->setEncryptedCipherKey($nonce.$encrypted);
    }

    /**
     * Create a new cipher key for a user
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     *
     * @throws EmptyCipherKeyException
     */
    public function createCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        $this->setCipherKey($this->encryptionAdapter->generateKey());
        $this->encryptCipherKey($user, $plainTextPassword);
    }

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
    public function encryptString(string $string, string $nonce = null): string
    {
        $this->startWatch(__METHOD__);
        if (null === $nonce) {
            $nonce = $this->encryptionAdapter->generateNonce();
        }
        $encrypted = $this->encryptionAdapter->encrypt($string, $nonce, $this->getCipherKey());
        $this->stopWatch(__METHOD__);

        return $nonce.$encrypted;
    }

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
    public function decryptString(string $encryptedString, string $nonce = null): string
    {
        $this->startWatch(__METHOD__);
        if (null === $nonce) {
            $nonce = $this->encryptionAdapter->parseNonce($encryptedString);
        }
        $decrypted = $this->encryptionAdapter->decrypt($encryptedString, $nonce, $this->getCipherKey());
        $this->stopWatch(__METHOD__);

        return $decrypted;
    }

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
    public function encryptStreamBlock($inputStream, string $nonce): string
    {
        $block = fread($inputStream, $this->encryptionAdapter->getClearTextBlockSize());
        if (false === $block) {
            throw new EncryptionException('Unable to read from clear-text stream');
        }

        return $this->encryptionAdapter->encrypt($block, $nonce, $this->getCipherKey());
    }

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
    public function decryptStreamBlock($inputStream, string $nonce): string
    {
        $encryptedBlock = fread($inputStream, $this->encryptionAdapter->getEncryptedBlockSize());
        if (false === $encryptedBlock) {
            throw new EncryptionException('Unable to read from encrypted stream');
        }

        return $this->encryptionAdapter->decrypt($encryptedBlock, $nonce, $this->getCipherKey());
    }

    /**
     * Encrypt a whole file by streaming each block from the input file to the output
     *
     * @param string $inputFilePath
     * @param string $outputFilePath
     *
     * @throws EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function encryptFile(string $inputFilePath, string $outputFilePath): void
    {
        $this->startWatch(__METHOD__);

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

        $this->stopWatch(__METHOD__);
    }

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
    public function decryptFile(string $inputFilePath, string $outputFilePath, int $fileSize = null): void
    {
        $this->startWatch(__METHOD__);

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

        $this->stopWatch(__METHOD__);
    }

    /**
     * @param resource $inputStream
     * @param resource $outputStream
     *
     * @throws EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function encryptStream($inputStream, $outputStream): void
    {
        $this->startWatch(__METHOD__);

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

        $this->stopWatch(__METHOD__);
    }

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
    public function decryptStream($inputStream, $outputStream, int $fileSize = null): void
    {
        $this->startWatch(__METHOD__);

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

        $this->stopWatch(__METHOD__);
    }

    /**
     * Set the current cipher-key used for encryption/decryption
     *
     * @param string $cipherKey
     *
     * @throws EmptyCipherKeyException
     */
    public function setCipherKey(string $cipherKey): void
    {
        if (!trim($cipherKey)) {
            throw new EmptyCipherKeyException('Trying to set an empty cipher key');
        }
        $this->cipherKey = $cipherKey;
        $this->session->set(self::SESSION_CIPHER_KEY, bin2hex($cipherKey));
    }

    /**
     * Get the current cipher-key used for encryption/decryption
     *
     * @throws EmptyCipherKeyException
     *
     * @return string
     */
    public function getCipherKey(): string
    {
        if (!$this->cipherKey) {
            $this->cipherKey = hex2bin($this->session->get(self::SESSION_CIPHER_KEY));
        }
        if (!trim($this->cipherKey)) {
            throw new EmptyCipherKeyException('Empty cipher key');
        }

        return $this->cipherKey;
    }

    /**
     * Set the ownership ID in session
     *
     * @param mixed $encryptionOwnershipId
     *
     * @throws EmptyOwnershipIdException
     */
    public function setEncryptionOwnershipId($encryptionOwnershipId): void
    {
        if (!trim($encryptionOwnershipId)) {
            throw new EmptyOwnershipIdException('Trying to set an empty ownership identifier');
        }
        $this->encryptionOwnershipId = $encryptionOwnershipId;
        $this->session->set(self::SESSION_OWNERSHIP_KEY, bin2hex($encryptionOwnershipId));
    }

    /**
     * Returns the ownership ID loaded in session
     *
     * @throws EmptyOwnershipIdException
     *
     * @return mixed
     */
    public function getEncryptionOwnershipId(): string
    {
        if (!$this->encryptionOwnershipId) {
            $this->encryptionOwnershipId = hex2bin($this->session->get(self::SESSION_OWNERSHIP_KEY));
        }
        if (!trim($this->encryptionOwnershipId)) {
            throw new EmptyOwnershipIdException('Empty ownership identifier');
        }

        return $this->encryptionOwnershipId;
    }

    /**
     * @param string $message
     *
     * @return string
     */
    public function parseNonce(string &$message): string
    {
        return $this->encryptionAdapter->parseNonce($message);
    }

    /**
     * @param string $name
     * @param string $category
     */
    protected function startWatch($name, $category = null): void
    {
        if ($this->stopwatch) {
            $this->stopwatch->start($name, $category);
        }
    }

    /**
     * @param string $name
     */
    protected function stopWatch($name): void
    {
        if ($this->stopwatch) {
            $this->stopwatch->stop($name);
        }
    }
}
