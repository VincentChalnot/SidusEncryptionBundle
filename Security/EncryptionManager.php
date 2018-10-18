<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
/** @noinspection EncryptionInitializationVectorRandomnessInspection */

namespace Sidus\EncryptionBundle\Security;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;
use Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException;
use Doctrine\Bundle\DoctrineBundle\Registry;
use Sidus\EncryptionBundle\Exception\FileHandlingException;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Stopwatch\Stopwatch;

/**
 * The encryption manager will handle the encryption/decryption of cipher key and data in the whole application
 * The cipher key is encrypted in the user with it's password (clear-text password) which means the cipher key can only
 * be retrieved at user's login. That's why it is passed along in the session (in clear form) This way the cypher-key is
 * never stored on the server (except in PHP's sessions) which means that the data are safe if the database or the
 * files are stolen. For improved security you can lower PHP's session duration.
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EncryptionManager
{
    protected static $cipherKeyType = 'aes-256-ecb';
    protected static $cipherDataType = 'aes-256-cbc';
    protected static $cipherKeySize = 32;
    protected static $blockSize = 32;
    protected static $ivSize = 16;

    protected const SESSION_CIPHER_KEY = 'sidus.encryption.cipherkey';
    protected const SESSION_OWNERSHIP_KEY = 'sidus.encryption.ownership';

    /** @var Session */
    protected $session;

    /** @var Registry */
    protected $doctrine;

    /** @var Stopwatch */
    protected $stopwatch;
    protected $autogenerateKey;
    protected $cipherKey;
    protected $encryptionOwnershipId;

    /**
     * Doctrine is only used when $autogenerateKey is set to true
     *
     * @param Session   $session
     * @param Registry  $doctrine
     * @param Stopwatch $stopwatch
     * @param bool      $autogenerateKey
     */
    public function __construct(
        Session $session,
        Registry $doctrine = null,
        Stopwatch $stopwatch = null,
        $autogenerateKey = false
    ) {
        $this->session = $session;
        $this->autogenerateKey = (bool) $autogenerateKey;
        $this->doctrine = $doctrine;
        $this->stopwatch = $stopwatch;
    }

    /**
     * Generate an initialization vector
     *
     * @return string
     */
    public function generateIv(): string
    {
        return random_bytes(static::$ivSize);
    }

    /**
     * Decrypt the cipher key used to encrypt/decrypt data using the user's password and saves it in the session
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     *
     * @throws \InvalidArgumentException
     * @throws EmptyCipherKeyException
     * @throws EmptyOwnershipIdException
     *
     * @return string
     */
    public function decryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): string
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        if ($this->autogenerateKey && $user->getEncryptedCipherKey()) {
            $this->createCipherKey($user, $plainTextPassword);
            $em = $this->doctrine->getManager();
            $em->persist($user);
            $em->flush();
        }
        $cipherKey = openssl_decrypt(
            $user->getEncryptedCipherKey(),
            static::$cipherKeyType,
            md5((string) $plainTextPassword),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        $this->setCipherKey($cipherKey);
        $this->setEncryptionOwnershipId($user->getEncryptionOwnershipId());

        return $cipherKey;
    }

    /**
     * Encrypt enterprise cipher key for a user
     * Used at user creation and password change
     * You need to persist the user after that
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     *
     * @throws EmptyCipherKeyException
     * @throws \InvalidArgumentException
     */
    public function encryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        $user->setEncryptedCipherKey(
            openssl_encrypt(
                $this->getCipherKey(),
                static::$cipherKeyType,
                md5((string) $plainTextPassword),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
            )
        );
    }

    /**
     * Create a new cipher key for a user
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     * @throws \InvalidArgumentException
     */
    public function createCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword): void
    {
        $cipherKey = random_bytes(static::$cipherKeySize);
        $this->setCipherKey($cipherKey);
        $this->encryptCipherKey($user, $plainTextPassword);
    }

    /**
     * Encrypt a string and automatically generate the IV if needed
     *
     * @param string $string
     * @param string $iv
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     *
     * @return string
     */
    public function encryptString($string, $iv = null): string
    {
        $this->startWatch(__METHOD__);
        if (!$iv) {
            $iv = $this->generateIv();
        }
        $encrypted = openssl_encrypt(
            $string,
            static::$cipherDataType,
            $this->getCipherKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        $this->stopWatch(__METHOD__);

        return $iv.$encrypted;
    }

    /**
     * Decrypt an encrypted string, try to parse the IV if not specified
     * Absolutely NOT safe for binary data
     *
     * @param string $encryptedString
     * @param string $iv
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     *
     * @return string
     */
    public function decryptString($encryptedString, $iv = null): string
    {
        $this->startWatch(__METHOD__);
        if (!$iv) {
            $iv = $this->parseIv($encryptedString);
        }
        $decrypted = openssl_decrypt(
            $encryptedString,
            static::$cipherDataType,
            $this->getCipherKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        $this->stopWatch(__METHOD__);

        return rtrim($decrypted, "\0");
    }

    /**
     * Encrypt a block of data from the input stream
     *
     * @param resource $inputStream
     * @param string   $iv
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     *
     * @return string
     */
    public function encryptStreamBlock($inputStream, $iv): string
    {
        $block = fread($inputStream, static::$blockSize);
        if (false === $block) {
            return false;
        }
        $encryptedBlock = openssl_encrypt(
            $block,
            static::$cipherDataType,
            $this->getCipherKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );

        return $encryptedBlock;
    }

    /**
     * Decrypt a block of the input stream
     * WARNING: the last block of a stream will be padded with \0 but we can't trim them automatically for binary data
     * so it's up to you to limit or trim the output
     *
     * @param resource $inputStream
     * @param string   $iv
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     *
     * @return string
     */
    public function decryptStreamBlock($inputStream, $iv): string
    {
        $encryptedBlock = fread($inputStream, static::$blockSize);
        if (false === $encryptedBlock) {
            return false;
        }
        $block = openssl_decrypt(
            $encryptedBlock,
            static::$cipherDataType,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            0,
            $iv
        );

        return $block;
    }

    /**
     * Encrypt a whole file by streaming each block from the input file to the output
     *
     * @param string $inputFilePath
     * @param string $outputFilePath
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function encryptFile($inputFilePath, $outputFilePath): void
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
     * @param resource $inputStream
     * @param resource $outputStream
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function encryptStream($inputStream, $outputStream): void
    {
        $this->startWatch(__METHOD__);

        $iv = $this->generateIv();
        if (false === fwrite($outputStream, $iv, static::$ivSize)) {
            throw new FileHandlingException('Unable to write to output stream');
        }

        while (!feof($inputStream)) {
            if (false === fwrite($outputStream, $this->encryptStreamBlock($inputStream, $iv))) {
                throw new FileHandlingException('Unable to write to output stream');
            }
        }

        $this->stopWatch(__METHOD__);
    }

    /**
     * Decrypt a file by streaming each block from the input to the output
     *
     * @see EncryptionManager::decryptStream WARNING !
     *
     * @param string $inputFilePath
     * @param string $outputFilePath
     * @param int    $fileSize
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function decryptFile($inputFilePath, $outputFilePath, $fileSize = null): void
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
     * Decrypt a stream
     * You can specify the original unencrypted file size in order to cut the output at the exact same location
     * WARNING If you don't specify a fileSize parameter, your output file will be padded with \0 so it will break
     * checksum verifications or even the file itself depending of the format.
     *
     * @param resource $inputStream
     * @param resource $outputStream
     * @param int      $fileSize
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\FileHandlingException
     */
    public function decryptStream($inputStream, $outputStream, $fileSize = null): void
    {
        $this->startWatch(__METHOD__);

        $iv = fread($inputStream, static::$ivSize);

        if (false === $iv) {
            throw new FileHandlingException('Unable to read IV from input stream');
        }

        $outputLength = $fileSize;
        $blockSize = static::$blockSize;

        while (!feof($inputStream)) {
            if (false === fwrite($outputStream, $this->decryptStreamBlock($inputStream, $iv), $outputLength)) {
                throw new FileHandlingException('Unable to write to output stream');
            }
            if ($fileSize) {
                $outputLength -= $blockSize;
            }
        }

        $this->stopWatch(__METHOD__);
    }

    /**
     * Parse the IV at the beginning of the input and cut it from the input
     *
     * @param string $input
     *
     * @return string
     */
    public function parseIv(&$input): string
    {
        $iv = substr($input, 0, static::$ivSize);
        $input = substr($input, static::$ivSize);

        return $iv;
    }

    /**
     * Set the current cipher-key used for encryption/decryption
     *
     * @param string $cipherKey
     *
     * @throws EmptyCipherKeyException
     */
    public function setCipherKey($cipherKey): void
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
     * @param int $encryptionOwnershipId
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
     * @return string
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
     * Wrap crypto_aead_*_encrypt() in a drop-dead-simple encryption interface
     *
     * @link https://paragonie.com/b/kIqqEWlp3VUOpRD7
     *
     * @param string $message
     * @param string $key
     *
     * @return string
     */
    protected function encrypt(string $message, string $key): string
    {
        $nonce = random_bytes(24); // NONCE = Number to be used ONCE, for each message
        $encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $message,
            $nonce,
            $nonce,
            $key
        );

        return $nonce.$encrypted;
    }

    /**
     * Wrap crypto_aead_*_decrypt() in a drop-dead-simple decryption interface
     *
     * @link https://paragonie.com/b/kIqqEWlp3VUOpRD7
     *
     * @param string $message - Encrypted message
     * @param string $key     - Encryption key
     *
     * @return string
     */
    protected function decrypt(string $message, string $key): string
    {
        $nonce = mb_substr($message, 0, 24, '8bit');
        $ciphertext = mb_substr($message, 24, null, '8bit');
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            $nonce,
            $nonce,
            $key
        );
        if (!is_string($plaintext)) {
            throw new Exception('Invalid message');
        }

        return $plaintext;
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
