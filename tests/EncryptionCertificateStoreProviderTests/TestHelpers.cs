
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xtrimmer.KeyStoreProvider.Certificate;

namespace Xtrimmer.EncryptionCertificateStoreProviderTests
{
    internal static class TestHelpers
    {
        /// <summary>
        /// Creates a new certificate.
        /// </summary>
        /// <param name="subject">Represents the distinguished name of the entity associated with the public key contained in the certificate.</param>
        /// <param name="storeLocation">Specifies the location of the certificate store.</param>
        /// <param name="hasPrivateKey">Specifies whether the certificate is created with a private key.</param>
        /// <returns>The certificate path.</returns>
        internal static string CreateCertificate(string subject, StoreLocation storeLocation, int keySizeInBits = 2048, bool hasPrivateKey = true)
        {
            const string KeyContainerName = "Xtrimmer.CertificateKeyStoreProvider";
            const string IPSecurityIkeIntermediate = "1.3.6.1.5.5.8.2.2";
            const string KeyRecovery = "1.3.6.1.4.1.311.10.3.11";

            CspParameters cspParameters = hasPrivateKey ? new CspParameters { KeyContainerName = KeyContainerName } : new CspParameters();

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySizeInBits, cspParameters))
            {
                CertificateRequest certificateRequest = new CertificateRequest(
                    subjectName: $"CN={subject}",
                    key: rsa,
                    hashAlgorithm: HashAlgorithmName.SHA256,
                    padding: RSASignaturePadding.Pkcs1);

                X509Extension keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: false);
                OidCollection oids = new OidCollection { new Oid(IPSecurityIkeIntermediate), new Oid(KeyRecovery) };
                X509Extension enhancedKeyUsage = new X509EnhancedKeyUsageExtension(oids, critical: true);
                X509Extension subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, critical: false);

                certificateRequest.CertificateExtensions.Add(keyUsage);
                certificateRequest.CertificateExtensions.Add(enhancedKeyUsage);
                certificateRequest.CertificateExtensions.Add(subjectKeyIdentifier);

                using (X509Certificate2 certificate = certificateRequest.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddDays(1460)
                ))
                {
                    X509Store store = new X509Store(StoreName.My, storeLocation);
                    store.Open(OpenFlags.MaxAllowed);
                    store.Add(certificate);
                    store.Close();

                    return $"{storeLocation}/{StoreName.My}/{certificate.Thumbprint}";
                }
            }
        }

        /// <summary>
        /// Removes the certificate if ound at the provided path. from the windows certificate store.
        /// </summary>
        /// <param name="path">the path to the certificte. Example: 'CurrentUser/My/BBF037EC4A133ADCA89FFAEC16CA5BFA8878FB94'</param>
        internal static void RemoveCertificate(string path)
        {
            if (path.IsNull())
            {
                return;
            }

            string[] pathParts = path.Split('/');

            if (pathParts.Length > 0)
            {
                string thumbprint = pathParts[pathParts.Length - 1];
                using (X509Store certificateStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    certificateStore.Open(OpenFlags.MaxAllowed);
                    X509Certificate2Collection matchingCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                    if (matchingCertificates.Count > 0)
                    {
                        foreach (X509Certificate2 certificate in matchingCertificates)
                        {
                            certificateStore.Remove(certificate);
                        }
                    }

                    certificateStore.Close();
                }
            }
        }

        /// <summary>
        /// Updates the encrypted key's embedded ciphertext size parameter.
        /// </summary>
        /// <param name="encryptedKeyEncryptionKey">The encrypted key within which the ciphertext size parameter is to be updated.</param>
        /// <param name="targetCiphertextSize">The new ciphertext size</param>
        /// <remarks>
        /// Changing the size parameter doesn't actually change the key size. It just changes the value for testing purposes.
        /// </remarks>
        internal static byte[] ChangeCiphertextLengthParameter(this byte[] encryptedKeyEncryptionKey, short targetCiphertextSize)
        {
            if (encryptedKeyEncryptionKey.Length >= 5)
            {
                byte[] newEncryptedKey = (byte[])encryptedKeyEncryptionKey.Clone();
                byte[] newLengthBytes = BitConverter.GetBytes(targetCiphertextSize);
                newEncryptedKey[3] = newLengthBytes[0];
                newEncryptedKey[4] = newLengthBytes[1];

                return newEncryptedKey;
            }
            else { throw new ArgumentException("The encryptedKeyEncryptionKey's length must be at least lenght 5."); }
        }

        /// <summary>
        /// Updates the encrypted key's embedded signature's size.
        /// </summary>
        /// <param name="encryptedKeyEncryptionKey">The encrypted key within which the signature size parameter is to be updated.</param>
        /// <param name="targetSignatureSize">The new signature size</param>
        internal static byte[] ChangeSignatureLength(this byte[] encryptedKeyEncryptionKey, short targetSignatureSize)
        {
            const int EncryptionKeyIdLengthIndex = 1;
            const int CipherTextLengthIndex = 3;
            const int KeyPathIndex = 5;

            short keyPathLength = BitConverter.ToInt16(encryptedKeyEncryptionKey, EncryptionKeyIdLengthIndex);
            int ciphertextLength = BitConverter.ToInt16(encryptedKeyEncryptionKey, CipherTextLengthIndex);
            int ciphertextIndex = KeyPathIndex + keyPathLength;
            int signatureIndex = ciphertextIndex + ciphertextLength;
            int signatureLength = encryptedKeyEncryptionKey.Length - signatureIndex;

            IEnumerable<byte> versionBytes = encryptedKeyEncryptionKey.Take(1);
            IEnumerable<byte> keyPathLengthBytes = encryptedKeyEncryptionKey.Skip(EncryptionKeyIdLengthIndex).Take(2);
            IEnumerable<byte> ciphertextLengthBytes = encryptedKeyEncryptionKey.Skip(CipherTextLengthIndex).Take(2);
            IEnumerable<byte> keyPathBytes = encryptedKeyEncryptionKey.Skip(KeyPathIndex).Take(keyPathLength);
            IEnumerable<byte> ciphertextBytes = encryptedKeyEncryptionKey.Skip(ciphertextIndex).Take(ciphertextLength);
            IEnumerable<byte> signatureBytes = encryptedKeyEncryptionKey.Skip(signatureIndex).Take(signatureLength);

            return versionBytes
                .Concat(keyPathLengthBytes)
                .Concat(ciphertextLengthBytes)
                .Concat(keyPathBytes)
                .Concat(ciphertextBytes)
                .Concat(signatureBytes.Take(targetSignatureSize))
                .ToArray();
        }

        /// <summary>
        /// Invalidates the signature by changing the last byte of the signature.
        /// </summary>
        /// <param name="encryptedKeyEncryptionKey">The encrypted key within which the signature is to be invalidated.</param>
        /// <returns>A new enctypted key with an invalidated signature.</returns>
        internal static byte[] InvalidateSignature(this byte[] encryptedKeyEncryptionKey)
        {
            byte[] newEncryptedKeyEncryptionKey = (byte[])encryptedKeyEncryptionKey.Clone();
            byte invalidationByte = (byte)(++newEncryptedKeyEncryptionKey[newEncryptedKeyEncryptionKey.Length - 1] % byte.MaxValue);
            newEncryptedKeyEncryptionKey[newEncryptedKeyEncryptionKey.Length - 1] = invalidationByte;

            return newEncryptedKeyEncryptionKey;
        }
    }
}
