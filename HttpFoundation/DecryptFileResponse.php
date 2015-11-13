<?php

namespace Sidus\EncryptionBundle\HttpFoundation;

use Sidus\EncryptionBundle\Entity\UserEncryptionProviderInterface;
use Sidus\EncryptionBundle\Security\EncryptionManager;
use SplFileInfo;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\HttpFoundation\Request;

/**
 * This type of response can be used to stream and decrypt an encrypted file at the same time, preventing the file from being
 * store unencrypted on the serveur.
 * 
 * @author Vincent Chalnot <vincent@sidus.fr>
 */
class DecryptFileResponse extends BinaryFileResponse
{
    /** @var int */
    protected $fileSize;

    /** @var EncryptionManager */
    protected $encryptionManager;

    /** @var UserEncryptionProviderInterface */
    protected $user;

    /** @var File */
    protected $file;

    /**
     * Initialize the response with the file path and the original's file size
     * The original file's size is very important to prevent the null character padding of the encryption function at the end of the file
     * which can introduce a slight difference in the filesize wich will break checksums verifications
     * 
     * @param EncryptionManager $encryptionManager
     * @param SplFileInfo|string $file
     * @param int $fileSize
     * @param int $status
     * @param array $headers
     * @param null|string $contentDisposition
     * @param bool $autoEtag
     * @param bool $autoLastModified
     */
    public function __construct(EncryptionManager $encryptionManager, $file, $fileSize, $status = 200, $headers = array(), $contentDisposition = null, $autoEtag = false, $autoLastModified = true)
    {
        parent::__construct($file, $status, $headers, false, $contentDisposition, $autoEtag, $autoLastModified);
        $this->setPrivate();
        $this->fileSize = $fileSize;
        $this->encryptionManager = $encryptionManager;
    }

    /**
     * @param Request $request
     * @return DecryptFileResponse
     */
    public function prepare(Request $request)
    {
        parent::prepare($request);
        $this->headers->set('Content-Length', $this->fileSize);
        $this->headers->set('Content-Type', 'application/octet-stream');
        return $this;
    }

    /**
     * Sends the file using the encryption manager with the php://output internal stream
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
