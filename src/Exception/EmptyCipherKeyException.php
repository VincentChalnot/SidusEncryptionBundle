<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\Exception;

/**
 * Thrown when there is no cipher key available to decrypt data
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EmptyCipherKeyException extends \RuntimeException implements EncryptionExceptionInterface
{
}
