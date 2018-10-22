<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\Authentication;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Registry\EncryptionManagerRegistry;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * The Authentication provider will be used at connection time to decrypt the cipher key in the user and store it in
 * session through the encryption manager.
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class AuthenticationProvider extends DaoAuthenticationProvider
{
    /** @var EncryptionManagerRegistry */
    protected $encryptionManagerRegistry;

    /**
     * @param EncryptionManagerRegistry $encryptionManagerRegistry
     */
    public function setEncryptionManagerRegistry(EncryptionManagerRegistry $encryptionManagerRegistry): void
    {
        $this->encryptionManagerRegistry = $encryptionManagerRegistry;
    }

    /**
     * Retrieve user with password token and use it to decrypt the cipher key in the user
     * The encryption manager will store it in the session for the following requests
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException
     */
    protected function retrieveUser($username, UsernamePasswordToken $token)
    {
        $user = parent::retrieveUser($username, $token);
        if ($user instanceof UserEncryptionProviderInterface && null !== $token->getCredentials()) {
            $encryptionManager = $this->encryptionManagerRegistry->getEncryptionManagerForUser($user);
            $encryptionManager->decryptCipherKey($user, $token->getCredentials());
        }

        return $user;
    }
}
