<?php

namespace Sidus\EncryptionBundle\Entity;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * This interface must be implemented on the User entity in order to store the encrypted cipher key
 * The plaintext cipher key must NOT be persisted to the database, the EncryptionManager will do all the job
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
interface UserEncryptionProviderInterface extends UserInterface
{
    /**
     * Must returns an encoded encrypted cipher key (encrypted by the plaintext password)
     * This value MUST be persisted to the database
     * It is strongly recommended to store this value as a base64 encoded string as it is a binary variable
     *
     * @return string $encryptedCipherKey
     */
    public function getEncryptedCipherKey(): string;

    /**
     * @param string $encryptedCipherKey
     */
    public function setEncryptedCipherKey($encryptedCipherKey): void;

    /**
     * Identifies a cipher key to encrypt/decrypt only related entities
     *
     * @return string|int
     */
    public function getEncryptionOwnershipId();
}
