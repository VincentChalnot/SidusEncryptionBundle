<?php

namespace Sidus\EncryptionBundle\EventSubscriber;

use Sidus\EncryptionBundle\Entity\CryptableInterface;
use Sidus\EncryptionBundle\Exception\EmptyOwnershipIdException;
use Sidus\EncryptionBundle\Security\EncryptionManager;
use Doctrine\Bundle\DoctrineBundle\Registry;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\Persistence\Event\LifecycleEventArgs;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Psr\Log\LoggerInterface;
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
    /** @var EncryptionManager */
    protected $encryptionManager;

    /** @var ArrayCollection */
    protected $flushedEntities;

    /** @var ArrayCollection */
    protected $alreadyDecryptedEntities;

    /** @var Registry */
    protected $doctrine;

    /** @var LoggerInterface */
    protected $logger;

    /**
     * @param EncryptionManager    $encryptionManager
     * @param Registry             $doctrine
     * @param LoggerInterface|null $logger
     */
    public function __construct(
        EncryptionManager $encryptionManager,
        Registry $doctrine,
        LoggerInterface $logger = null
    ) {
        $this->flushedEntities = new ArrayCollection();
        $this->alreadyDecryptedEntities = new ArrayCollection();
        $this->encryptionManager = $encryptionManager;
        $this->doctrine = $doctrine;
        $this->logger = $logger;
    }

    /**
     * @return array
     */
    public function getSubscribedEvents()
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
    public function postLoad(LifecycleEventArgs $event)
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
    public function onFlush(OnFlushEventArgs $eventArgs)
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
     * @param PostFlushEventArgs $eventArgs
     *
     * @throws \Symfony\Component\PropertyAccess\Exception\UnexpectedTypeException
     * @throws \Symfony\Component\PropertyAccess\Exception\AccessException
     * @throws \Symfony\Component\PropertyAccess\Exception\InvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function postFlush(PostFlushEventArgs $eventArgs)
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
    protected function decryptEntity(CryptableInterface $entity)
    {
        if (false === $entity->getIsEncrypted()) {
            $this->alreadyDecryptedEntities->add($entity);
            $this->logError('Entity already decrypted', $entity);

            return;
        }
        try {
            $ownershipId = $this->encryptionManager->getEncryptionOwnershipId();
        } catch (EmptyOwnershipIdException $e) {
            $this->logError('Missing ownership ID on entity', $entity, $e);

            return;
        }
        if ((string) $entity->getEncryptionOwnershipId() !== (string) $ownershipId) {
            $this->logError('Wrong ownership ID on entity', $entity);

            return;
        }
        $propertyAccessor = PropertyAccess::createPropertyAccessor();
        foreach ($entity->getEncryptedProperties() as $property) {
            $data = base64_decode($propertyAccessor->getValue($entity, $property));
            if (!$data) {
                $this->logError("Empty data for property {$property}", $entity);
                continue;
            }
            $propertyAccessor->setValue($entity, $property, $this->encryptionManager->decryptString($data));
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
     *
     * @return bool
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    protected function cryptEntity(CryptableInterface $entity, EntityManager $em)
    {
        if (true === $entity->getIsEncrypted()) {
            $this->logError('Entity already encrypted', $entity);

            return false;
        }
        try {
            $ownershipId = $this->encryptionManager->getEncryptionOwnershipId();
        } catch (EmptyOwnershipIdException $e) {
            $this->logError('Missing ownership ID on entity', $entity, $e);

            return false;
        }
        if ((string) $entity->getEncryptionOwnershipId() !== (string) $ownershipId) {
            $this->logError('Wrong ownership ID on entity', $entity);

            return false;
        }
        $uow = $em->getUnitOfWork();
        $cs = $uow->getEntityChangeSet($entity);
        $hasChanges = false;
        $propertyAccessor = PropertyAccess::createPropertyAccessor();
        foreach ($entity->getEncryptedProperties() as $property) {
            $iv = null;
            // If Entity was already decrypted, we need to encrypt all properties even if there is no change
            if (!$this->alreadyDecryptedEntities->contains($entity)) {
                if (!array_key_exists($property, $cs)) {
                    continue;
                }
                $oldValue = $cs[$property][0];
                if ($oldValue) { // If existing iv, use this one
                    $iv = $this->encryptionManager->parseIv($oldValue);
                    if (strlen($iv) !== $this->encryptionManager->getIvSize()) {
                        $iv = null;
                    }
                }
            }
            $newEncryptedValue = $this->encryptionManager->encryptString(
                $propertyAccessor->getValue($entity, $property),
                $iv
            );
            $propertyAccessor->setValue($entity, $property, base64_encode($newEncryptedValue));
            $hasChanges = true;
        }
        $entity->setIsEncrypted(true);
        if ($hasChanges) {
            $class = $em->getClassMetadata(get_class($entity));
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
    protected function logError($message, CryptableInterface $entity = null, \Exception $e = null)
    {
        if (!$this->logger) {
            return;
        }
        try {
            $context = [
                'encryptionOwnershipId' => $this->encryptionManager->getEncryptionOwnershipId(),
            ];
        } catch (EmptyOwnershipIdException $e) {
            $context = [
                'encryptionOwnershipId' => null,
            ];
        }
        if ($entity) {
            $meta = $this->doctrine->getManager()->getClassMetadata(get_class($entity));
            $context['entity'] = [
                'class' => get_class($entity),
                'identifier' => $meta->getIdentifierValues($entity),
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
