using Microsoft.Data.Encryption.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using static Xtrimmer.KeyStoreProvider.Certificate.Properties.Resources;

namespace Xtrimmer.KeyStoreProvider.Certificate
{
    /// <summary>
    /// The implementation of the key store provider for Windows Certificate Store. 
    /// This class enables using certificates stored in the Windows Certificate Store as key encryption keys.
    /// </summary>
    public class CertificateKeyStoreProvider : EncryptionKeyStoreProvider
    {
        private const string HashingAlgorithm = "SHA256";
        private const int Version = 1;

        /// <inheritdoc/>
        public override string ProviderName { get; } = "CERTIFICATE_STORE";

        /// <inheritdoc/>
        /// <remarks>
        /// The format of the key path should be "LocalMachine/My/<certificate_thumbprint>" or "CurrentUser/My/<certificate_thumbprint>".
        /// </remarks>
        public override byte[] UnwrapKey(string encryptionKeyId, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedKey)
        {
            encryptionKeyId.ValidateNotNullOrWhitespace(nameof(encryptionKeyId));
            encryptedKey.ValidateNotNull(nameof(encryptedKey));
            encryptedKey.ValidateNotEmpty(nameof(encryptedKey));
            ValidateVersionByte(encryptedKey);
            ValidateCertificatePathLength(encryptionKeyId);

            return GetOrCreateDataEncryptionKey(encryptedKey.ToHexString(), UnwrapKey);

            byte[] UnwrapKey()
            {
                X509Certificate2 certificate = GetCertificateByPath(encryptionKeyId);
                int keySizeInBytes = certificate.PublicKey.Key.KeySize / 8;

                const int EncryptionKeyIdLengthIndex = 1;
                const int CipherTextLengthIndex = 3;
                const int KeyPathIndex = 5;

                short keyPathLength = BitConverter.ToInt16(encryptedKey, EncryptionKeyIdLengthIndex);
                int ciphertextLength = BitConverter.ToInt16(encryptedKey, CipherTextLengthIndex);
                ValidateCiphertextLength(keySizeInBytes, ciphertextLength, encryptionKeyId);

                int ciphertextIndex = KeyPathIndex + keyPathLength;
                int signatureIndex = ciphertextIndex + ciphertextLength;
                int signatureLength = encryptedKey.Length - signatureIndex;
                ValidateSignatureLength(keySizeInBytes, signatureLength, encryptionKeyId);

                IEnumerable<byte> ciphertext = encryptedKey.Skip(ciphertextIndex).Take(ciphertextLength);

                ValidateSignature(encryptedKey, certificate, signatureIndex, encryptionKeyId);

                return Unwrap(ciphertext, certificate);
            }
        }

        /// <inheritdoc/>
        /// <remarks>
        /// The format of the key path should be "LocalMachine/My/<certificate_thumbprint>" or "CurrentUser/My/<certificate_thumbprint>".
        /// </remarks>
        public override byte[] WrapKey(string encryptionKeyId, KeyEncryptionKeyAlgorithm algorithm, byte[] key)
        {
            encryptionKeyId.ValidateNotNullOrWhitespace(nameof(encryptionKeyId));
            key.ValidateNotNull(nameof(key));
            key.ValidateNotEmpty(nameof(key));
            ValidateCertificatePathLength(encryptionKeyId);

            X509Certificate2 certificate = GetCertificateByPath(encryptionKeyId);

            byte[] version = new byte[] { Version };
            byte[] encryptionKeyIdBytes = Encoding.Unicode.GetBytes(encryptionKeyId.ToLowerInvariant());
            byte[] encryptionKeyIdLength = BitConverter.GetBytes((short)encryptionKeyIdBytes.Length);
            byte[] cipherText = RSAEncrypt(key, certificate);
            byte[] cipherTextLength = BitConverter.GetBytes((short)cipherText.Length);
            byte[] preHashMessage = version.Concat(encryptionKeyIdLength).Concat(cipherTextLength).Concat(encryptionKeyIdBytes).Concat(cipherText).ToArray();
            byte[] hash = ComputeSha256Hash(preHashMessage);
            byte[] signature = RSASignHashedData(hash, certificate);
            byte[] encryptedColumnEncryptionKey = preHashMessage.Concat(signature).ToArray();

            return encryptedColumnEncryptionKey;
        }

        /// <inheritdoc/>
        public override byte[] Sign(string encryptionKeyId, bool allowEnclaveComputations)
        {
            encryptionKeyId.ValidateNotNullOrWhitespace(nameof(encryptionKeyId));
            ValidateCertificatePathLength(encryptionKeyId);

            var hash = ComputeKeyEncryptionKeyMetadataHash(encryptionKeyId, allowEnclaveComputations);
            X509Certificate2 certificate = GetCertificateByPath(encryptionKeyId);

            byte[] signature = RSASignHashedData(hash, certificate);

            return signature;
        }

        /// <inheritdoc/>
        public override bool Verify(string encryptionKeyId, bool allowEnclaveComputations, byte[] signature)
        {
            encryptionKeyId.ValidateNotNullOrWhitespace(nameof(encryptionKeyId));
            ValidateCertificatePathLength(encryptionKeyId);
            signature.ValidateNotNull(nameof(signature));
            signature.ValidateNotEmpty(nameof(signature));

            return GetOrCreateSignatureVerificationResult(
                keyInformation: Tuple.Create(encryptionKeyId, allowEnclaveComputations, signature.ToHexString()),
                createItem: Verify
            );

            bool Verify()
            {
                var hash = ComputeKeyEncryptionKeyMetadataHash(encryptionKeyId, allowEnclaveComputations);
                X509Certificate2 certificate = GetCertificateByPath(encryptionKeyId);

                return VerifySignature(hash, signature, certificate);
            }
        }

        #region Private Methods

        /// <summary>
        /// Computes the SHA256 hash.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private static byte[] ComputeSha256Hash(byte[] message)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(message);
            }
        }

        /// <summary>
        /// Computes the key encryption key metadata SHA256 hash.
        /// </summary>
        /// <param name="encryptionKeyId"></param>
        /// <param name="allowEnclaveComputations"></param>
        /// <returns></returns>
        private byte[] ComputeKeyEncryptionKeyMetadataHash(string encryptionKeyId, bool allowEnclaveComputations)
        {
            string keyEncryptionKeyMetadata = ProviderName + encryptionKeyId + allowEnclaveComputations;
            byte[] keyEncryptionKeyMetadataBytes = Encoding.Unicode.GetBytes(keyEncryptionKeyMetadata.ToLowerInvariant());

            return ComputeSha256Hash(keyEncryptionKeyMetadataBytes);
        }

        /// <summary>
        /// Parses the given certificate path, searches in certificate store and returns a matching certificate
        /// </summary>
        /// <param name="encryptionKeyId">
        /// Certificate key path. Format of the path is [LocalMachine|CurrentUser]/[storename]/thumbprint
        /// </param>
        /// <param name="isSystemOp"></param>
        /// <returns>Returns the certificate identified by the certificate path</returns>
        private X509Certificate2 GetCertificateByPath(string encryptionKeyId)
        {
            string[] certificatePathParts = encryptionKeyId.Split('/');
            ValidateCertificatePathFormat(certificatePathParts);
            StoreLocation storeLocation = certificatePathParts.Length > 2 ? ParseStoreLocation(certificatePathParts[0]) : StoreLocation.LocalMachine;
            StoreName storeName = StoreName.My;
            string thumbprint = certificatePathParts[certificatePathParts.Length - 1];
            thumbprint.ValidateNotEmpty(nameof(thumbprint));

            return GetCertificate(storeLocation, storeName, encryptionKeyId, thumbprint);

            StoreLocation ParseStoreLocation(string s) => (StoreLocation)Enum.Parse(typeof(StoreLocation), s);
        }

        /// <summary>
        /// Searches for a certificate in certificate store and returns the matching certificate
        /// </summary>
        /// <param name="storeLocation">Store Location: This can be one of LocalMachine or CurrentUser.</param>
        /// <param name="storeName">Store Location: Currently this can only be My store.</param>
        /// <param name="encryptionKeyId">The certificate path.</param>
        /// <param name="thumbprint">Certificate thumbprint</param>
        /// <returns>Matching certificate</returns>
        private X509Certificate2 GetCertificate(StoreLocation storeLocation, StoreName storeName, string encryptionKeyId, string thumbprint)
        {
            using (X509Store certificateStore = new X509Store(storeName, storeLocation))
            {
                certificateStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection matchingCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                ValidateCertificateIsFound(storeLocation, storeName, thumbprint, matchingCertificates);
                X509Certificate2 certificate = matchingCertificates[0];
                ValidateCertificateHasPrivateKey(encryptionKeyId, certificate);

                return certificate;
            }
        }

        /// <summary>
        /// Encrypt the text using specified certificate.
        /// </summary>
        /// <param name="plainText">Text to encrypt.</param>
        /// <param name="certificate">Certificate object.</param>
        /// <returns>Returns an encrypted blob or throws an exception if there are any errors.</returns>
        private byte[] RSAEncrypt(byte[] plainText, X509Certificate2 certificate)
        {
            RSA rsa = certificate.GetRSAPublicKey();
            return rsa.Encrypt(plainText, RSAEncryptionPadding.OaepSHA1);
        }

        /// <summary>
        /// Encrypt the text using specified certificate.
        /// </summary>
        /// <param name="cipherText">Text to decrypt.</param>
        /// <param name="certificate">Certificate object.</param>
        private byte[] Unwrap(IEnumerable<byte> cipherText, X509Certificate2 certificate)
        {
            RSA rsa = certificate.GetRSAPrivateKey();
            return rsa.Decrypt(cipherText.ToArray(), RSAEncryptionPadding.OaepSHA1);
        }

        /// <summary>
        /// Generates signature based on RSA PKCS#v1.5 scheme using a specified certificate. 
        /// </summary>
        /// <param name="dataToSign">Text to sign.</param>
        /// <param name="certificate">Certificate object.</param>
        /// <returns>Signature</returns>
        private byte[] RSASignHashedData(byte[] dataToSign, X509Certificate2 certificate)
        {
            RSA rsa = certificate.GetRSAPrivateKey();
            AsymmetricSignatureFormatter asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(rsa);
            asymmetricSignatureFormatter.SetHashAlgorithm(HashingAlgorithm);

            return asymmetricSignatureFormatter.CreateSignature(dataToSign);
        }

        /// <summary>
        /// Verifies the given RSA PKCSv1.5 signature.
        /// </summary>
        /// <param name="hash">The data used to verify.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="certificate">The certificate.</param>
        /// <returns>true if signature is valid, false if it is not valid</returns>
        private bool VerifySignature(IEnumerable<byte> hash, IEnumerable<byte> signature, X509Certificate2 certificate)
        {
            RSA rsa = certificate.GetRSAPrivateKey();
            AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            asymmetricSignatureDeformatter.SetHashAlgorithm(HashingAlgorithm);

            return asymmetricSignatureDeformatter.VerifySignature(hash.ToArray(), signature.ToArray());
        }

        #region Validation Logic

        private static void ValidateCertificateIsFound(StoreLocation storeLocation, StoreName storeName, string thumbprint, X509Certificate2Collection matchingCertificates)
        {
            if (matchingCertificates == null || matchingCertificates.Count == 0)
            {
                throw new ArgumentException(CertificateNotFound.Format(thumbprint, storeName, storeLocation));
            }
        }

        private static void ValidateCertificateHasPrivateKey(string encryptionKeyId, X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
            {
                throw new ArgumentException(CertificateWithoutPrivateKey.Format(encryptionKeyId));
            }
        }

        private static void ValidateCertificatePathFormat(string[] certificatePathParts)
        {
            if (certificatePathParts.Length > 3)
            {
                throw new ArgumentException(CertificatePathPartsExceedsThree);
            }

            if (certificatePathParts.Length > 2 && !IsLocalMachine(certificatePathParts[0]) && !IsCurrentUser(certificatePathParts[0]))
            {
                throw new ArgumentException(UnsupportedCertificateStoreLocation);
            }

            if (certificatePathParts.Length > 1 && !IsMy(certificatePathParts[certificatePathParts.Length - 2]))
            {
                throw new ArgumentException(UnsupportedCertificateStoreName);
            }

            bool IsLocalMachine(string s) => string.Equals(s, StoreLocation.LocalMachine.ToString(), StringComparison.OrdinalIgnoreCase);
            bool IsCurrentUser(string s) => string.Equals(s, StoreLocation.CurrentUser.ToString(), StringComparison.OrdinalIgnoreCase);
            bool IsMy(string s) => string.Equals(s, StoreName.My.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        private void ValidateCertificatePathLength(string encryptionKeyId)
        {
            if (encryptionKeyId.Length >= short.MaxValue)
            {
                throw new ArgumentException(CertificatePathLengthTooLong.Format(short.MaxValue));
            }
        }

        private static void ValidateVersionByte(byte[] encryptedKey)
        {
            if (encryptedKey[0] != Version)
            {
                throw new ArgumentException(InvalidVersionByte);
            }
        }

        private static void ValidateCiphertextLength(int keySizeInBytes, int cipherTextLength, string encryptionKeyId)
        {
            if (cipherTextLength != keySizeInBytes)
            {
                throw new ArgumentException(UnexpectedCiphertextLength.Format(cipherTextLength, keySizeInBytes, encryptionKeyId));
            }
        }

        private static void ValidateSignatureLength(int keySizeInBytes, int signatureLength, string encryptionKeyId)
        {
            if (signatureLength != keySizeInBytes)
            {
                throw new ArgumentException(UnexpectedSignatureLength.Format(signatureLength, keySizeInBytes, encryptionKeyId));
            }
        }

        private void ValidateSignature(IEnumerable<byte> encryptedKey, X509Certificate2 certificate, int signatureIndex, string encryptionKeyId)
        {
            byte[] hash = ComputeSha256Hash(encryptedKey.Take(signatureIndex).ToArray());

            if (!VerifySignature(hash, encryptedKey.Skip(signatureIndex).ToArray(), certificate))
            {
                throw new ArgumentException(InvalidSignature.Format(encryptionKeyId));
            }
        }

        #endregion

        #endregion
    }
}
