<?php

namespace Sidus\EncryptionBundle\Exception;

/**
 * Class FileHandlingException
 * @package Sidus\EncryptionBundle\Exception
 * Throw when function like fopen, fread, fwrite return false
 */
class FileHandlingException extends \RuntimeException
{
}