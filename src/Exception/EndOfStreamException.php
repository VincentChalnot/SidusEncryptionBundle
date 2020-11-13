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
 * Can occurs when the encrypted data end unexpectedly
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class EndOfStreamException extends \RuntimeException implements EncryptionExceptionInterface
{
}
