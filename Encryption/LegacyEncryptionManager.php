<?php /** @noinspection CryptographicallySecureAlgorithmsInspection */

namespace Sidus\EncryptionBundle\Encryption;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Stopwatch\Stopwatch;

/**
 * Legacy version of the LegacyEncryptionManager with custom methods only for
 * cipher-key encryption and decryption
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 *
 * @property Rijndael256MCryptEncryptionAdapter $encryptionAdapter
 */
class LegacyEncryptionManager extends EncryptionManager
{
    /**
     * @param Rijndael256MCryptEncryptionAdapter $encryptionAdapter
     * @param Session                            $session
     * @param Stopwatch|null                     $stopwatch
     */
    public function __construct(
        Rijndael256MCryptEncryptionAdapter $encryptionAdapter,
        Session $session,
        Stopwatch $stopwatch = null
    ) {
        parent::__construct($encryptionAdapter, $session, $stopwatch);
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
        if (null === $encryptedCipherKey) {
            throw new EmptyCipherKeyException('Empty encrypted cipher key');
        }
        $cipherKey = $this->encryptionAdapter->decryptCipherKey(
            $encryptedCipherKey,
            md5((string) $plainTextPassword)
        );
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
        $encrypted = $this->encryptionAdapter->encryptCipherKey(
            $this->getCipherKey(),
            md5((string) $plainTextPassword)
        );

        $user->setEncryptedCipherKey($encrypted);
    }
}
