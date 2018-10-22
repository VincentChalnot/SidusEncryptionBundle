<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\Session;

use Sidus\EncryptionBundle\Exception\EmptyCipherKeyException;
use Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException;

/**
 * Handles cipher key storage across multiple request
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
interface CipherKeyStorageInterface
{
    /**
     * Set the current cipher-key used for encryption/decryption
     *
     * @param string $cipherKey
     *
     * @throws EmptyCipherKeyException
     */
    public function setCipherKey(string $cipherKey): void;

    /**
     * Get the current cipher-key used for encryption/decryption
     *
     * @throws EmptyCipherKeyException
     *
     * @return string
     */
    public function getCipherKey(): string;

    /**
     * Set the ownership ID in session
     *
     * @param mixed $encryptionOwnershipId
     *
     * @throws EmptyOwnershipIdException
     */
    public function setEncryptionOwnershipId($encryptionOwnershipId): void;

    /**
     * Returns the ownership ID loaded in session
     *
     * @throws EmptyOwnershipIdException
     *
     * @return mixed
     */
    public function getEncryptionOwnershipId(): string;
}
