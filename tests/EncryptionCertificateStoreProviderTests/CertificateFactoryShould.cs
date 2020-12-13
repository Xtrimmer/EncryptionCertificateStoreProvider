using Microsoft.Data.Encryption.Cryptography;
using System;
using System.Security.Cryptography.X509Certificates;
using Xunit;

using static Xtrimmer.KeyStoreProvider.Certificate.CertificateFactory;

namespace Xtrimmer.EncryptionCertificateStoreProviderTests
{
    public sealed class CertificateFactoryShould : IDisposable
    {
        private const string TestCertName = "TestCertificate";
        private KeyEncryptionKey KeyEncryptionKey { get; set; }

        [Theory]
        [DataAttributes.NullOrWhitespaceData]
        public void ThrowWhenSubjectIsNullOrWhitespace(string subject)
        {
            Assert.Throws<ArgumentException>(() => CreateCertificateKeyEncryptionKey(subject, StoreLocation.CurrentUser));
        }

        [Fact]
        public void CreateCertificateCorrectly()
        {
            KeyEncryptionKey = CreateCertificateKeyEncryptionKey(TestCertName, StoreLocation.CurrentUser);
            X509Certificate2 certificate;

            string thumbprint = KeyEncryptionKey.Path.Split('/')[2];

            using (X509Store certificateStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                certificateStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection matchingCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                Assert.True(matchingCertificates.Count > 0);

                certificate = matchingCertificates[0];

                Assert.True(certificate.HasPrivateKey);
                Assert.True(certificate.GetRSAPublicKey() != null);
                Assert.True(certificate.GetRSAPrivateKey() != null);
            }
        }

        public void Dispose()
        {
            if (KeyEncryptionKey != null)
            {
                string[] pathParts = KeyEncryptionKey.Path.Split('/');

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
                                if (certificate.Subject == $"CN={TestCertName}")
                                {
                                    certificateStore.Remove(certificate);
                                }
                            }
                        }

                        certificateStore.Close();
                    }
                }

                KeyEncryptionKey = null;
            }
        }
    }
}
