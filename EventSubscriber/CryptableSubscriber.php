<?php

namespace Sidus\EncryptionBundle\EventSubscriber;

use Sidus\EncryptionBundle\Entity\CryptableInterface;
use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
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
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * This subscriber is called just after entities are loaded from the database and just before they are persisted to it
 * It will encrypt and decrypt all the properties of the Cryptable entities so they are never stored in plain text anywhere
 * 
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class CryptableSubscriber implements EventSubscriber
{
    /** @var ContainerInterface */
    protected $container;

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
     * We need to inject the container to avoid a circular reference
     *
     * @param ContainerInterface $container
     */
    public function __construct(ContainerInterface $container)
    {
        $this->flushedEntities = new ArrayCollection;
        $this->alreadyDecryptedEntities = new ArrayCollection;
        $this->container = $container;
        $this->encryptionManager = $container->get('sidus.encryption.manager');
        $this->doctrine = $container->get('doctrine');
        if ($container->has('logger')) {
            $this->logger = $container->get('logger');
        }
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
     */
    protected function decryptEntity(CryptableInterface $entity)
    {
        if (!$this->getUser()) {
            $this->logError("Cannot encrypt entity with no user in security context", $entity);
            return;
        }
        if (false === $entity->getIsEncrypted()) {
            $this->alreadyDecryptedEntities->add($entity);
            $this->logError("Entity already decrypted", $entity);
            return;
        }
        try {
            $ownershipId = $this->encryptionManager->getEncryptionOwnershipId();
        } catch (EmptyOwnershipIdException $e) {
            $this->logError("Missing ownership ID on entity", $entity, $e);
            return;
        }
        if ((string) $entity->getEncryptionOwnershipId() !== (string) $ownershipId) {
            $this->logError("Wrong ownership ID on entity", $entity);
            return;
        }
        foreach ($entity->getEncryptedProperties() as $property) {
            $getter = 'get' . ucfirst($property);
            $setter = 'set' . ucfirst($property);
            $data = base64_decode($entity->$getter());
            if (!$data) {
                $this->logError("Empty data for property {$property}", $entity);
                continue;
            }
            $entity->$setter($this->encryptionManager->decryptString($data));
        }
        $entity->setIsEncrypted(false);
    }

    /**
     * @param CryptableInterface $entity
     * @param EntityManager $em
     * @return bool
     */
    protected function cryptEntity(CryptableInterface $entity, EntityManager $em)
    {
        if (!$this->getUser()) {
            $this->logError("Cannot encrypt entity with no user in security context", $entity);
            return false;
        }
        if (true === $entity->getIsEncrypted()) {
            $this->logError("Entity already encrypted", $entity);
            return false;
        }
        try {
            $ownershipId = $this->encryptionManager->getEncryptionOwnershipId();
        } catch (EmptyOwnershipIdException $e) {
            $this->logError("Missing ownership ID on entity", $entity, $e);
            return false;
        }
        if ((string) $entity->getEncryptionOwnershipId() !== (string) $ownershipId) {
            $this->logError("Wrong ownership ID on entity", $entity);
            return false;
        }
        $uow = $em->getUnitOfWork();
        $cs = $uow->getEntityChangeSet($entity);
        $hasChanges = false;
        foreach ($entity->getEncryptedProperties() as $property) {
            $iv = null;
            // If Entity was already decrypted, we need to encrypt all properties even if there is no change
            if (!$this->alreadyDecryptedEntities->contains($entity)) {
                if (!isset($cs[$property])) {
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
            $getter = 'get' . ucfirst($property);
            $setter = 'set' . ucfirst($property);
            $newEncryptedValue = $this->encryptionManager->encryptString($entity->$getter(), $iv);
            $entity->$setter(base64_encode($newEncryptedValue));
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
     * @param string $message
     * @param CryptableInterface $entity
     * @param \Exception $e
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
        $this->logger->error('EncryptionBundle:CryptableSubscriber - ' . $message, $context);
    }

    /**
     * Get a user from the Security Context
     *
     * @return UserEncryptionProviderInterface|null
     * @see TokenInterface::getUser()
     */
    protected function getUser()
    {
        $token = $this->container->get('security.context')->getToken();
        if (!$token) {
            return null;
        }

        $user = $token->getUser();
        if ($user instanceof UserEncryptionProviderInterface) {
            return $user;
        }
        return null;
    }
}
