Sidus/EncryptionBundle
====================

Easy entity and file encryption for Symfony2.

We wanted to be able to store encrypted data in our Symfony2 applications and we realized that there were no simple way to do it.

In our solution, a malicious user will have a really hard time to steal data from our server.

 - The data will not be compromised by an SQL Injection or by a remote include attack.
 - If no end users are connected, no one can decrypt the data, not even the root user.
 - Only users from the same organization can share data between each other.

The idea is to store the cipher key inside the database in the user table but encrypted with the user's plaintext password. This way each user from the same organization can share the same cipher key to encrypt and decrypt data but each user can only decrypt it's own encrypted key at login time.

The main weakness of this system is that the cipher key is stored temporarly in PHP's session, however,  the only way to overcome this problem would be to use a pretty complex asymmetric encryption system between the client and the server which could only be done properly using a rich client.

Helpers
-------
This bundle comes with an EncryptionManager class which can be used in standalone to encrypt and decrypt data and files.
There's also a DecryptFileResponse which allows you to directly stream an encrypted file to the client while deciphering it.

Installation
------------
You just require the package `sidus/encryption-bundle` either directly in your composer.json or by command line :
```
$ composer require sidus/encryption-bundle ~0.1.0
```

Update your `AppKernel.php`
```
public function registerBundles()
{
    $bundles = array(
        ...
        new Sidus\EncryptionBundle\SidusEncryptionBundle(),
    );

    ...
}
```

Implements the interfaces
-------------------------

You should implements the UserEncryptionProviderInterface on your user entity and the CryptableInterface on each entity
that will contains encrypted data.

Don't forget to update the model, the encryptedCipherKey must be persisted to the database !

Configuration
-------------
If you need to share encrypted data between users you need to generate each encrypted cipher key with the same cipher
key which can prove to be tricky, especially if users already have accounts and passwords.

If each user encrypts it's own data however, you can just use the automatic encryption key generation in your config.yml:
```
sidus_encryption:
    encryption_key:
        auto_generate: false
```
This will tell the system to automatically generate a new encryption key if the user doesn't have any.

In case of password recovery, the user won't be able to retrieve any of the encrypted data because he would be the only
one able to decrypt the cipher key.

Apache License
--------------
@todo

Authors
-------

The bundle was originally created by [Vincent Chalnot](https://github.com/VincentChalnot).
