<?php

namespace Sidus\EncryptionBundle\Entity;

/**
 * This interface identifies the entities that have to be encrypted during doctrine's Flush event and be decrypted at
 * postLoad You need to return a array of the properties that needs to be encrypted and decrypted
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
interface CryptableInterface
{
    /**
     * Returns an array of property names
     *
     * @return array
     */
    public function getEncryptedProperties();

    /**
     * Returns if entity is encrypted
     *
     * @return bool
     */
    public function getIsEncrypted();

    /**
     * Set the encryption state of the entity
     *
     * @param bool $bool
     *
     * @return CryptableInterface
     */
    public function setIsEncrypted($bool);

    /**
     * Identifies a cipher key to encrypt/decrypt only related entities
     *
     * @return string|int
     */
    public function getEncryptionOwnershipId();

    /**
     * Store the ownership identifier
     *
     * @param string|int $ownershipId
     */
    public function setEncryptionOwnershipId($ownershipId);
}
