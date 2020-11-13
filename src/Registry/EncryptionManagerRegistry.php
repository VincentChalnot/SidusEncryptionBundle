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
    private array $managers;
    private string $defaultCode;
    
    /**
     * EncryptionManagerRegistry constructor.
     *
     * @param string   $defaultCode
     * @param iterable|\Traversable $managers
     */
    public function __construct(string $defaultCode, iterable $managers)
    {
        $this->managers = iterator_to_array($managers);
        $this->defaultCode = $defaultCode;
    }

    /**
     * @return EncryptionManagerInterface[]
     */
    public function getEncryptionManagers(): array
    {
        return $this->managers;
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

        return $this->managers[$code];
    }

    public function hasEncryptionManager(string $code): bool
    {
        return array_key_exists($code, $this->managers);
    }
    
    public function getDefaultEncryptionManager(): EncryptionManagerInterface
    {
        return $this->getEncryptionManager($this->defaultCode);
    }
}
