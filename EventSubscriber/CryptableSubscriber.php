<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\EventSubscriber;

use Sidus\EncryptionBundle\Entity\CryptableInterface;
use Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\Persistence\Event\LifecycleEventArgs;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Psr\Log\LoggerInterface;
use Sidus\EncryptionBundle\Registry\EncryptionManagerRegistry;
use Sidus\EncryptionBundle\Session\CipherKeyStorageInterface;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * This subscriber is called just after entities are loaded from the database and just before they are persisted to it
 * It will encrypt and decrypt all the properties of the Cryptable entities so they are never stored in plain text
 * anywhere
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class CryptableSubscriber implements EventSubscriber
{
    /** @var CipherKeyStorageInterface */
    protected $cipherKeyStorage;

    /** @var EncryptionManagerRegistry */
    protected $encryptionManagerRegistry;

    /** @var ArrayCollection */
    protected $flushedEntities;

    /** @var ArrayCollection */
    protected $alreadyDecryptedEntities;

    /** @var LoggerInterface */
    protected $logger;

    /**
     * @param CipherKeyStorageInterface $cipherKeyStorage
     * @param EncryptionManagerRegistry $encryptionManagerRegistry
     * @param LoggerInterface|null      $logger
     */
    public function __construct(
        CipherKeyStorageInterface $cipherKeyStorage,
        EncryptionManagerRegistry $encryptionManagerRegistry,
        LoggerInterface $logger = null
    ) {
        $this->cipherKeyStorage = $cipherKeyStorage;
        $this->encryptionManagerRegistry = $encryptionManagerRegistry;
        $this->logger = $logger;
        $this->flushedEntities = new ArrayCollection();
        $this->alreadyDecryptedEntities = new ArrayCollection();
    }

    /**
     * @return array
     */
    public function getSubscribedEvents(): array
    {
        return [
            'onFlush',
            'postLoad',
            'postFlush',
        ];
    }

    /**
     * Decrypt a Cryptable entity just after it is loaded from the database
     *
     * @param LifecycleEventArgs $event
     *
     * @throws \Symfony\Component\PropertyAccess\Exception\UnexpectedTypeException
     * @throws \Symfony\Component\PropertyAccess\Exception\AccessException
     * @throws \Symfony\Component\PropertyAccess\Exception\InvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function postLoad(LifecycleEventArgs $event): void
    {
        $entity = $event->getObject();
        if (!$entity instanceof CryptableInterface) {
            return;
        }
        $this->decryptEntity($entity);
    }

    /**
     * Encrypt all Cryptable entities just before they are be persisted to the database
     *
     * @param OnFlushEventArgs $eventArgs
     *
     * @throws \Doctrine\ORM\ORMInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \Symfony\Component\PropertyAccess\Exception\UnexpectedTypeException
     * @throws \Symfony\Component\PropertyAccess\Exception\AccessException
     * @throws \Symfony\Component\PropertyAccess\Exception\InvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function onFlush(OnFlushEventArgs $eventArgs): void
    {
        $em = $eventArgs->getEntityManager();
        $uow = $em->getUnitOfWork();
        foreach ($uow->getScheduledEntityInsertions() as $entity) {
            if ($entity instanceof CryptableInterface) {
                $this->cryptEntity($entity, $em);
            }
        }
        foreach ($uow->getScheduledEntityUpdates() as $entity) {
            if ($entity instanceof CryptableInterface) {
                $this->cryptEntity($entity, $em);
            }
        }
    }

    /**
     * Restore all flushed entities to their decrypted state
     *
     * @throws \Symfony\Component\PropertyAccess\Exception\UnexpectedTypeException
     * @throws \Symfony\Component\PropertyAccess\Exception\AccessException
     * @throws \Symfony\Component\PropertyAccess\Exception\InvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function postFlush(): void
    {
        foreach ($this->flushedEntities as $entity) {
            $this->decryptEntity($entity);
        }
        $this->flushedEntities->clear();
    }

    /**
     * @param CryptableInterface $entity
     *
     * @throws \Symfony\Component\PropertyAccess\Exception\UnexpectedTypeException
     * @throws \Symfony\Component\PropertyAccess\Exception\AccessException
     * @throws \Symfony\Component\PropertyAccess\Exception\InvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    protected function decryptEntity(CryptableInterface $entity): void
    {
        if (false === $entity->getIsEncrypted()) {
            $this->alreadyDecryptedEntities->add($entity);
            $this->logError('Entity already decrypted', $entity);

            return;
        }
        try {
            $ownershipId = $this->cipherKeyStorage->getEncryptionOwnershipId();
        } catch (EmptyOwnershipIdException $e) {
            $this->logError('Missing ownership ID on entity', $entity, $e);

            return;
        }
        if ((string) $entity->getEncryptionOwnershipId() !== (string) $ownershipId) {
            $this->logError('Wrong ownership ID on entity', $entity);

            return;
        }
        $encryptionManager = $this->encryptionManagerRegistry->getEncryptionManagerForEntity($entity);
        $propertyAccessor = PropertyAccess::createPropertyAccessor();
        foreach ($entity->getEncryptedProperties() as $property) {
            $data = base64_decode($propertyAccessor->getValue($entity, $property));
            if (!$data) {
                $this->logError("Empty data for property {$property}", $entity);
                continue;
            }
            $propertyAccessor->setValue($entity, $property, $encryptionManager->decryptString($data));
        }
        $entity->setIsEncrypted(false);
    }

    /**
     * @param CryptableInterface $entity
     * @param EntityManager      $em
     *
     * @throws \Symfony\Component\PropertyAccess\Exception\InvalidArgumentException
     * @throws \Symfony\Component\PropertyAccess\Exception\AccessException
     * @throws \Symfony\Component\PropertyAccess\Exception\UnexpectedTypeException
     * @throws \InvalidArgumentException
     * @throws \Doctrine\ORM\ORMInvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     *
     * @return bool
     */
    protected function cryptEntity(CryptableInterface $entity, EntityManager $em): bool
    {
        if (true === $entity->getIsEncrypted()) {
            $this->logError('Entity already encrypted', $entity);

            return false;
        }
        try {
            $ownershipId = $this->cipherKeyStorage->getEncryptionOwnershipId();
        } catch (EmptyOwnershipIdException $e) {
            $this->logError('Missing ownership ID on entity', $entity, $e);

            return false;
        }
        if ((string) $entity->getEncryptionOwnershipId() !== (string) $ownershipId) {
            $this->logError('Wrong ownership ID on entity', $entity);

            return false;
        }
        $encryptionManager = $this->encryptionManagerRegistry->getEncryptionManagerForEntity($entity);

        $uow = $em->getUnitOfWork();
        $hasChanges = false;
        $propertyAccessor = PropertyAccess::createPropertyAccessor();
        foreach ($entity->getEncryptedProperties() as $property) {
            $value = $propertyAccessor->getValue($entity, $property);
            if (null === $value) {
                continue;
            }
            // If Entity was already decrypted, we need to encrypt all properties even if there is no change
            $newEncryptedValue = $encryptionManager->encryptString($value);
            $propertyAccessor->setValue($entity, $property, base64_encode($newEncryptedValue));
            $hasChanges = true;
        }
        $entity->setIsEncrypted(true);
        if ($hasChanges) {
            $class = $em->getClassMetadata(\get_class($entity));
            $uow->recomputeSingleEntityChangeSet($class, $entity);
        }
        $this->flushedEntities->add($entity);

        return $hasChanges;
    }

    /**
     * @param string             $message
     * @param CryptableInterface $entity
     * @param \Exception         $e
     *
     * @throws \InvalidArgumentException
     */
    protected function logError($message, CryptableInterface $entity = null, \Exception $e = null): void
    {
        if (!$this->logger) {
            return;
        }
        try {
            $context = [
                'encryptionOwnershipId' => $this->cipherKeyStorage->getEncryptionOwnershipId(),
            ];
        } catch (EmptyOwnershipIdException $e) {
            $context = [
                'encryptionOwnershipId' => null,
            ];
        }
        if ($entity) {
            $context['entity'] = [
                'class' => \get_class($entity),
                'identifier' => $entity->getIdentifier(),
                'encrypted' => $entity->getIsEncrypted(),
                'encryptionOwnershipId' => $entity->getEncryptionOwnershipId(),
                'encryptedProperties' => $entity->getEncryptedProperties(),
            ];
        }
        if ($e) {
            $context['exception'] = $e;
        }
        $this->logger->error('EncryptionBundle:CryptableSubscriber - '.$message, $context);
    }
}
