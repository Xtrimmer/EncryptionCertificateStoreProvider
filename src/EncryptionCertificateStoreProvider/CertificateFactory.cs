using Microsoft.Data.Encryption.Cryptography;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Xtrimmer.KeyStoreProvider.Certificate
{
    public static class CertificateFactory
    {
        public static KeyEncryptionKey CreateCertificateKeyEncryptionKey(string subject, StoreLocation location, bool isEnclaveSupported = false)
        {
            subject.ValidateNotNullOrWhitespace(nameof(subject));

            const string KeyContainerName = "Xtrimmer.CertificateKeyStoreProvider";
            const string IPSecurityIkeIntermediate = "1.3.6.1.5.5.8.2.2";
            const string KeyRecovery = "1.3.6.1.4.1.311.10.3.11";

            CspParameters cspParameters = new CspParameters { KeyContainerName = KeyContainerName };

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, cspParameters))
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
                    X509Store store = new X509Store(StoreName.My, location);
                    store.Open(OpenFlags.MaxAllowed);
                    store.Add(certificate);
                    store.Close();

                    string certificatePath = $"{location}/{StoreName.My}/{certificate.Thumbprint}";

                    return new KeyEncryptionKey(subject, certificatePath, new CertificateKeyStoreProvider(), isEnclaveSupported);
                }
            }
        }
    }
}
