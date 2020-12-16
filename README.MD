
[![Build Status](https://dev.azure.com/Xtrimmer/EncryptionCertificateStoreProvider/_apis/build/status/Xtrimmer.EncryptionCertificateStoreProvider?branchName=master)](https://dev.azure.com/Xtrimmer/EncryptionCertificateStoreProvider/_build/latest?definitionId=4&branchName=master)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=alert_status)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=coverage)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)  
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=bugs)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=code_smells)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=security_rating)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)  
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=ncloc)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=Xtrimmer_EncryptionCertificateStoreProvider&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=Xtrimmer_EncryptionCertificateStoreProvider)

# EncryptionCertificateStoreProvider

`EncryptionCertificateStoreProvider` is an implementation of the ***Microsoft.Data.Encryption.Cryptography.EncryptionKeyStoreProvider*** for Windows Certificate Store. 
This package enables using certificates stored in the Windows Certificate Store as key encryption keys with the ***Microsoft.Data.Encryption.Cryptography*** library.

# Certificate Store Provider Basics
## Windows Certificate  Store Locations
Certificates can be stored in the following certificate store locations:
- **CurrentUser** - This type of certificate store is local to a user account on the computer. This certificate store is located in the registry under the HKEY_CURRENT_USER root.
- **LocalMachine** - This type of certificate store is local to the computer and is global to all users on the computer. This certificate store is located in the registry under the HKEY_LOCAL_MACHINE root.

For each system store location, the certificate will be placed in predefined systems stores, '*My*'.
## Permissions for provisioning a certificate key encryption key
- **LocalMachine** - you must have Read access to the certificate that is used as a key encryption key, or be the administrator on the computer.


## Create a `KeyEncryptionKey` by generating a new certificate
#### `CreateCertificateKeyEncryptionKey` Arguments
- **subject** - Represents the distinguished name of the entity associated with the public key contained in the certificate.
- **location** - Specifies the location of the certificate store.
- **isEnclaveSupported** - Specifies that the key encryption key is enclave-enabled. You can share all data encryption keys, encrypted with the key encryption key, with a server-side secure enclave and use them for computations inside the enclave.

```csharp
    // Create a new KeyEncryptionKey by generating a new certificate in the CurrentUser location.
    KeyEncryptionKey keyEncryptionKey = CertificateFactory.CreateCertificateKeyEncryptionKey(
        subject: "My New Certificate", 
        location: StoreLocation.CurrentUser, 
        isEnclaveSupported: true
    );

    // Create a new ProtectedDataEncryptionKey protected by the newly created certificate KeyEncryptionKey.
    DataEncryptionKey dataEncryptionKey = new ProtectedDataEncryptionKey("My new DEK", keyEncryptionKey);

    // Use the new ProtectedDataEncryptionKey to encrypt and decrypt information.
    string plaintext = "Hello World!";
    byte[] ciphertext = plaintext.Encrypt(dataEncryptionKey);
    string originalPlaintext = ciphertext.Decrypt<string>(dataEncryptionKey); 
```

## Create a `KeyEncryptionKey` by loading an existing certificate
#### `KeyEncryptionKey` Arguments:
- **name** - The name of the key encryption key. This can be any string and will be used to identify the key in encryption metadata.
- **path** - The path of the key in the windows certificate store. 

    Key path format: ***CertificateStoreLocation/CertificateStoreName/CertificateThumbprint***
    
    Examples:
    ```
    CurrentUser/My/BBF037EC4A133ADCA89FFAEC16CA5BFA8878FB94
    LocalMachine/My/CA5BFA8878FB94BBF037EC4A133ADCA89FFAEC16
    ``` 
- **keyStoreProvider** - A key store provider is a client-side software component that holds a key store that has the key encryption key.
- **isEnclaveSupported** - Specifies that the key encryption key is enclave-enabled. You can share all data encryption keys, encrypted with the key encryption key, with a server-side secure enclave and use them for computations inside the enclave.

```csharp
    // Create a new KeyEncryptionKey by loading an existing certificate in the CurrentUser location.
    KeyEncryptionKey keyEncryptionKey = new KeyEncryptionKey(
        name: "My New KEK", 
        path: "CurrentUser/My/BBF037EC4A133ADCA89FFAEC16CA5BFA8878FB94", 
        keyStoreProvider: new CertificateKeyStoreProvider(), 
        isEnclaveSupported: true
    );

    // Create a new ProtectedDataEncryptionKey protected by the certificate KeyEncryptionKey.
    DataEncryptionKey dataEncryptionKey = new ProtectedDataEncryptionKey(name: "My new DEK", keyEncryptionKey);

    // Use the new ProtectedDataEncryptionKey to encrypt and decrypt information.
    string plaintext = "Hello World!";
    byte[] ciphertext = plaintext.Encrypt(dataEncryptionKey);
    string originalPlaintext = ciphertext.Decrypt<string>(dataEncryptionKey); 
```
