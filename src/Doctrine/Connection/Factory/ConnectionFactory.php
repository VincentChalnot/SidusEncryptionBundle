<?php

namespace Sidus\EncryptionBundle\Doctrine\Connection\Factory;

use Doctrine\Common\EventManager;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Driver\AbstractMySQLDriver;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception\DriverException;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Sidus\EncryptionBundle\Doctrine\Type\EncryptTypeInterface;
use Sidus\EncryptionBundle\Registry\EncryptionManagerRegistry;

/**
 * The default Doctrine's connection factory should be override to allow injection the encryption manager into the type.
 */
class ConnectionFactory
{
    private array $typesConfig;
    private bool $initialized = false;

    private EncryptionManagerRegistry $encryptionManager;

    public function __construct(array $typesConfig, EncryptionManagerRegistry $encryptionManager)
    {
        $this->typesConfig = $typesConfig;
        $this->encryptionManager = $encryptionManager;
    }

    /**
     * Create a connection by name.
     *
     * @param mixed[]         $params
     * @param string[]|Type[] $mappingTypes
     *
     * @return Connection
     */
    public function createConnection(array $params, Configuration $config = null, EventManager $eventManager = null, array $mappingTypes = []): Connection
    {
        if (! $this->initialized) {
            $this->initializeTypes();
        }

        if (! isset($params['pdo']) && ! isset($params['charset'])) {
            $wrapperClass = null;
            if (isset($params['wrapperClass'])) {
                if (! is_subclass_of($params['wrapperClass'], Connection::class)) {
                    throw \Doctrine\DBAL\Exception::invalidWrapperClass($params['wrapperClass']);
                }

                $wrapperClass           = $params['wrapperClass'];
                $params['wrapperClass'] = null;
            }

            $connection = DriverManager::getConnection($params, $config, $eventManager);
            $params     = $connection->getParams();
            $driver     = $connection->getDriver();

            if ($driver instanceof AbstractMySQLDriver) {
                $params['charset'] = 'utf8mb4';

                if (! isset($params['defaultTableOptions']['collate'])) {
                    $params['defaultTableOptions']['collate'] = 'utf8mb4_unicode_ci';
                }
            } else {
                $params['charset'] = 'utf8';
            }

            if ($wrapperClass !== null) {
                $params['wrapperClass'] = $wrapperClass;
            } else {
                $wrapperClass = Connection::class;
            }

            $connection = new $wrapperClass($params, $driver, $config, $eventManager);
        } else {
            $connection = DriverManager::getConnection($params, $config, $eventManager);
        }

        if (! empty($mappingTypes)) {
            $platform = $this->getDatabasePlatform($connection);
            foreach ($mappingTypes as $dbType => $doctrineType) {
                $platform->registerDoctrineTypeMapping($dbType, $doctrineType);
            }
        }

        return $connection;
    }

    /**
     * Try to get the database platform.
     *
     * This could fail if types should be registered to an predefined/unused connection
     * and the platform version is unknown.
     * For details have a look at DoctrineBundle issue #673.
     *
     * @throws \Doctrine\DBAL\Exception
     */
    private function getDatabasePlatform(Connection $connection) : AbstractPlatform
    {
        try {
            return $connection->getDatabasePlatform();
        } catch (DriverException $driverException) {
            throw new \Doctrine\DBAL\Exception(
                'An exception occurred while establishing a connection to figure out your platform version.' . PHP_EOL .
                "You can circumvent this by setting a 'server_version' configuration value" . PHP_EOL . PHP_EOL .
                'For further information have a look at:' . PHP_EOL .
                'https://github.com/doctrine/DoctrineBundle/issues/673',
                0,
                $driverException
            );
        }
    }

    /**
     * initialize the types
     */
    private function initializeTypes() : void
    {
        foreach ($this->typesConfig as $typeName => $typeConfig) {
            if (Type::hasType($typeName)) {
                Type::overrideType($typeName, $typeConfig['class']);
            } else {
                Type::addType($typeName, $typeConfig['class']);
            }
            $type = Type::getType($typeName);

            if ($type instanceof EncryptTypeInterface) {
                $type->setEncryptionManager($this->encryptionManager->getDefaultEncryptionManager());
            }
        }
        $this->initialized = true;
    }
}
