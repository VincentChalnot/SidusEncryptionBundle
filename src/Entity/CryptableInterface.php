<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
     * Must return the adapter code needed to decrypt this entity, this can either be a constant or be variable for each
     * entity
     *
     * @return string
     */
    public function getEncryptionAdapterCode(): string;

    /**
     * Returns an array of property names
     *
     * @return array
     */
    public function getEncryptedProperties(): array;

    /**
     * Returns if entity is encrypted
     *
     * @return bool
     */
    public function getIsEncrypted(): bool;
    
    /**
     * Set the encryption state of the entity
     *
     * @param bool $bool
     */
    public function setIsEncrypted(bool $bool): void;

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
    public function setEncryptionOwnershipId($ownershipId): void;

    /**
     * @return string|int
     */
    public function getIdentifier();
}
