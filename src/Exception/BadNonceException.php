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
 * Thrown when a message doesn't contain the nonce
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class BadNonceException extends \RuntimeException implements EncryptionExceptionInterface
{
}
