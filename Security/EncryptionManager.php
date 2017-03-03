<?php

namespace Sidus\EncryptionBundle\Security;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;
use Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException;
use Doctrine\Bundle\DoctrineBundle\Registry;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Stopwatch\Stopwatch;

/**
 * The encryption manager will handle the encrytion/decryption of cipher key and data in the whole application
 * The cipher key is encrypted in the user with it's password (cleartext password) which means the cipher key can only
 * be retrieved at user's login. That's why it is passed along in the session (in clear form) This way the cyperkey is
 * never stored on the server (except in php's sessions) which means that the data are safe if the database or the
 * files are stolen. For improved security you can lower PHP's session duration.
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EncryptionManager
{
    protected static $cipherKeyType = MCRYPT_RIJNDAEL_256;
    protected static $cipherKeyMode = MCRYPT_MODE_ECB;
    protected static $cipherDataType = MCRYPT_RIJNDAEL_256;
    protected static $cipherDataMode = MCRYPT_MODE_CBC;

    const SESSION_CIPHER_KEY = 'sidus.encryption.cipherkey';
    const SESSION_OWNERSHIP_KEY = 'sidus.encryption.ownership';

    /** @var Session */
    protected $session;

    /** @var Registry */
    protected $doctrine;

    /** @var Stopwatch */
    protected $stopwatch;
    protected $autogenerateKey;
    protected $cipherKey;
    protected $blockSize;
    protected $encryptionOwnershipId;

    /**
     * Doctrine is only used when autogenerateKey is set to true
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
    public function generateIv()
    {
        return mcrypt_create_iv($this->getIvSize(), MCRYPT_DEV_URANDOM);
    }

    /**
     * Decrypt the cipher key used to encrypt/decrypt entreprise data using the user's password and saves it in the
     * session
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
    public function decryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword)
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
        $cipherKey = mcrypt_decrypt(
            $this::$cipherKeyType,
            md5((string) $plainTextPassword),
            $user->getEncryptedCipherKey(),
            $this::$cipherKeyMode
        );
        $this->setCipherKey($cipherKey);
        $this->setEncryptionOwnershipId($user->getEncryptionOwnershipId());

        return $cipherKey;
    }

    /**
     * Encrypt entreprise cipher key for a user
     * Used at user creation and password change
     * You need to persist the user after that
     *
     * @param UserEncryptionProviderInterface $user
     * @param string                          $plainTextPassword
     *
     * @throws EmptyCipherKeyException
     * @throws \InvalidArgumentException
     */
    public function encryptCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword)
    {
        if (!trim($plainTextPassword)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }
        $user->setEncryptedCipherKey(
            mcrypt_encrypt(
                $this::$cipherKeyType,
                md5((string) $plainTextPassword),
                $this->getCipherKey(),
                $this::$cipherKeyMode
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
    public function createCipherKey(UserEncryptionProviderInterface $user, $plainTextPassword)
    {
        $cipherKey = openssl_random_pseudo_bytes(mcrypt_get_key_size($this::$cipherDataType, $this::$cipherDataMode));
        $this->setCipherKey($cipherKey);
        $this->encryptCipherKey($user, $plainTextPassword);
    }

    /**
     * Encrypt a string and automatically generate the IV if needed
     *
     * @param string $string
     * @param string $iv
     *
     * @return string
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function encryptString($string, $iv = null)
    {
        $this->startWatch(__METHOD__);
        if (!$iv) {
            $iv = $this->generateIv();
        }
        $encrypted = mcrypt_encrypt(
            $this::$cipherDataType,
            $this->getCipherKey(),
            $string,
            $this::$cipherDataMode,
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
     * @return string
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function decryptString($encryptedString, $iv = null)
    {
        $this->startWatch(__METHOD__);
        if (!$iv) {
            $iv = $this->parseIv($encryptedString);
        }
        $decrypted = mcrypt_decrypt(
            $this::$cipherDataType,
            $this->getCipherKey(),
            $encryptedString,
            $this::$cipherDataMode,
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
     * @return boolean
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function encryptStreamBlock($inputStream, $iv)
    {
        $block = fread($inputStream, $this->getBlockSize());
        if ($block === false) {
            return false;
        }
        $encryptedBlock = mcrypt_encrypt(
            $this::$cipherDataType,
            $this->getCipherKey(),
            $block,
            $this::$cipherDataMode,
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
     * @return boolean
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function decryptStreamBlock($inputStream, $iv)
    {
        $encryptedBlock = fread($inputStream, $this->getBlockSize());
        if ($encryptedBlock === false) {
            return false;
        }
        $block = mcrypt_decrypt(
            $this::$cipherDataType,
            $this->getCipherKey(),
            $encryptedBlock,
            $this::$cipherDataMode,
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
     */
    public function encryptFile($inputFilePath, $outputFilePath)
    {
        $this->startWatch(__METHOD__);
        $inputStream = fopen($inputFilePath, 'rb');
        $outputStream = fopen($outputFilePath, 'wb');

        $iv = $this->generateIv();
        fwrite($outputStream, $iv, $this->getIvSize());

        while (!feof($inputStream)) {
            fwrite($outputStream, $this->encryptStreamBlock($inputStream, $iv));
        }

        fclose($inputStream);
        fclose($outputStream);
        $this->stopWatch(__METHOD__);
    }

    /**
     * Decrypt a file by streaming each block from the input to the output
     * You can specify the original unencrypted file size in order to cut the output at the exact same location
     * WARNING If you don't specify a fileSize parameter, your output file will be padded with \0 so it will break
     * checksum verifications or even the file itself depending of the format.
     *
     * @param string $inputFilePath
     * @param string $outputFilePath
     * @param int    $fileSize
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function decryptFile($inputFilePath, $outputFilePath, $fileSize = null)
    {
        $this->startWatch(__METHOD__);
        $inputStream = fopen($inputFilePath, 'rb');
        $outputStream = fopen($outputFilePath, 'wb');

        $iv = fread($inputStream, $this->getIvSize());

        $outputLenght = $fileSize;
        $blockSize = $this->getBlockSize();

        while (!feof($inputStream)) {
            fwrite($outputStream, $this->decryptStreamBlock($inputStream, $iv), $outputLenght);
            if ($fileSize) {
                $outputLenght -= $blockSize;
            }
        }

        fclose($outputStream);
        fclose($inputStream);
        $this->stopWatch(__METHOD__);
    }

    /**
     * Get the block size of the cipher used for data encryption/decryption
     * 32 for RIJNDAEL 256 in CBC
     *
     * @return int
     */
    public function getBlockSize()
    {
        if (!$this->blockSize) {
            /** @noinspection PhpMethodParametersCountMismatchInspection */
            $this->blockSize = mcrypt_get_block_size($this::$cipherDataType, $this::$cipherDataMode);
        }

        return $this->blockSize;
    }

    /**
     * Get the IV size of the cipher used for data encryption/decryption
     * 32 for RIJNDAEL 256 in CBC
     *
     * @return int
     */
    public function getIvSize()
    {
        return mcrypt_get_iv_size($this::$cipherDataType, $this::$cipherDataMode);
    }

    /**
     * Parse the IV at the begining of the input and cut it from the input
     *
     * @param string $input
     *
     * @return string
     */
    public function parseIv(&$input)
    {
        $iv = substr($input, 0, $this->getIvSize());
        $input = substr($input, $this->getIvSize());

        return $iv;
    }

    /**
     * Set the current cipherkey used for encryption/decryption
     *
     * @param string $cipherKey
     *
     * @throws EmptyCipherKeyException
     */
    public function setCipherKey($cipherKey)
    {
        if (!trim($cipherKey)) {
            throw new EmptyCipherKeyException('Trying to set an empty cipher key');
        }
        $this->cipherKey = $cipherKey;
        $this->session->set(self::SESSION_CIPHER_KEY, bin2hex($cipherKey));
    }

    /**
     * Get the current cipherkey used for encryption/decryption
     *
     * @return string
     * @throws EmptyCipherKeyException
     */
    public function getCipherKey()
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
    public function setEncryptionOwnershipId($encryptionOwnershipId)
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
     * @return string
     * @throws EmptyOwnershipIdException
     */
    public function getEncryptionOwnershipId()
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
     * @param string $name
     * @param string $category
     */
    protected function startWatch($name, $category = null)
    {
        if ($this->stopwatch) {
            $this->stopwatch->start($name, $category);
        }
    }

    /**
     * @param string $name
     */
    protected function stopWatch($name)
    {
        if ($this->stopwatch) {
            $this->stopwatch->stop($name);
        }
    }
}
