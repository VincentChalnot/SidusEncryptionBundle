<?php
/*
 * This file is part of the Sidus/EncryptionBundle package.
 *
 * Copyright (c) 2015-2018 Vincent Chalnot
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sidus\EncryptionBundle\HttpFoundation;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Manager\EncryptionManagerInterface;
use SplFileInfo;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * This type of response can be used to stream and decrypt an encrypted file at the same time, preventing the file from
 * being store unencrypted on the server.
 *
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class DecryptFileResponse extends BinaryFileResponse
{
    protected int $fileSize;
    protected EncryptionManagerInterface $encryptionManager;
    protected UserEncryptionProviderInterface $user;
    
    /**
     * Initialize the response with the file path and the original's file size
     * The original file's size is very important to prevent the null character padding of the encryption function at
     * the end of the file which can introduce a slight difference in the file size which will break checksum
     * verifications
     *
     * @param EncryptionManagerInterface $encryptionManager
     * @param SplFileInfo|string         $file
     * @param int                        $fileSize
     * @param int                        $status
     * @param array                      $headers
     * @param null|string                $contentDisposition
     * @param bool                       $autoEtag
     * @param bool                       $autoLastModified
     */
    public function __construct(
        EncryptionManagerInterface $encryptionManager,
        $file,
        int $fileSize,
        int $status = 200,
        array $headers = [],
        ?string $contentDisposition = null,
        bool $autoEtag = false,
        bool $autoLastModified = true
    ) {
        parent::__construct($file, $status, $headers, false, $contentDisposition, $autoEtag, $autoLastModified);
        $this->setPrivate();
        $this->fileSize = $fileSize;
        $this->encryptionManager = $encryptionManager;
    }

    /**
     * @param Request $request
     *
     * @return DecryptFileResponse
     */
    public function prepare(Request $request): DecryptFileResponse
    {
        parent::prepare($request);
        $this->headers->set('Content-Length', $this->fileSize);

        return $this;
    }

    /**
     * Sends the file using the encryption manager with the php://output internal stream
     *
     * @throws \Sidus\EncryptionBundle\Exception\EmptyCipherKeyException
     */
    public function sendContent()
    {
        if (!$this->isSuccessful()) {
            parent::sendContent();

            return;
        }

        $this->encryptionManager->decryptFile($this->file->getPathname(), 'php://output', $this->fileSize);
    }
}
