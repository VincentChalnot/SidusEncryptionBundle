<?php

namespace Sidus\EncryptionBundle\Registry;

use Sidus\EncryptionBundle\Entity\CryptableInterface;
use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Manager\EncryptionManagerInterface;

/**
 * Registry for all available encryption managers (one for each adapter)
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EncryptionManagerRegistry
{
    /** @var EncryptionManagerInterface[] */
    protected $encryptionManagers = [];

    /** @var string */
    protected $preferredEncryptionManager;

    /**
     * @param string $preferredEncryptionManager
     */
    public function __construct(string $preferredEncryptionManager)
    {
        $this->preferredEncryptionManager = $preferredEncryptionManager;
    }

    /**
     * @return EncryptionManagerInterface[]
     */
    public function getEncryptionManagers(): array
    {
        return $this->encryptionManagers;
    }

    /**
     * @param string                     $code
     * @param EncryptionManagerInterface $encryptionManager
     */
    public function addEncryptionManager(string $code, EncryptionManagerInterface $encryptionManager): void
    {
        $this->encryptionManagers[$code] = $encryptionManager;
    }

    /**
     * @param CryptableInterface $entity
     *
     * @return EncryptionManagerInterface
     */
    public function getEncryptionManagerForEntity(CryptableInterface $entity): EncryptionManagerInterface
    {
        return $this->getEncryptionManager($entity->getEncryptionAdapterCode());
    }

    /**
     * @param UserEncryptionProviderInterface $user
     *
     * @return EncryptionManagerInterface
     */
    public function getEncryptionManagerForUser(UserEncryptionProviderInterface $user): EncryptionManagerInterface
    {
        return $this->getEncryptionManager($user->getEncryptionAdapterCode());
    }

    /**
     * @param string $code
     *
     * @throws \UnexpectedValueException
     *
     * @return EncryptionManagerInterface
     */
    public function getEncryptionManager(string $code): EncryptionManagerInterface
    {
        if (!$this->hasEncryptionManager($code)) {
            throw new \UnexpectedValueException("Missing encryption manager {$code}");
        }

        return $this->encryptionManagers[$code];
    }

    /**
     * @param string $code
     *
     * @return bool
     */
    public function hasEncryptionManager(string $code): bool
    {
        return array_key_exists($code, $this->encryptionManagers);
    }

    /**
     * @return EncryptionManagerInterface
     */
    public function getPreferredEncryptionManager(): EncryptionManagerInterface
    {
        return $this->getEncryptionManager($this->preferredEncryptionManager);
    }
}
