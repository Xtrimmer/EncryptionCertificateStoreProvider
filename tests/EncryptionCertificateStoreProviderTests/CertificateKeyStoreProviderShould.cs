using Microsoft.Data.Encryption.Cryptography;
using System;
using Xunit;
using Xtrimmer.KeyStoreProvider.Certificate;
using static Microsoft.Data.Encryption.Cryptography.KeyEncryptionKeyAlgorithm;
using System.Linq;

using static Xtrimmer.KeyStoreProvider.Certificate.Properties.Resources;

namespace Xtrimmer.EncryptionCertificateStoreProviderTests
{
    public sealed class CertificateKeyStoreProviderShould
    {
        [Theory]
        [DataAttributes.NullOrWhitespaceData]
        public void ThrowWhenUnwrapKeyCalledWithNullOrWhitespaceEncryptionKeyId(string encryptionKeyId)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(encryptionKeyId, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(NullOrWhitespaceString.Format("encryptionKeyId"), ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWithNullEncryptedKey()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentNullException>(() => provider.UnwrapKey("testPath", RSA_OAEP, null));
            Assert.Contains(NullArgument.Format("encryptedKey", typeof(byte[])), ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWithEmptyEncryptedKey()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("testPath", RSA_OAEP, new byte[] { }));
            Assert.Contains(EmptySequence.Format("encryptedKey"), ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWithInvalidVersionedEncryptedKey()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("testPath", RSA_OAEP, new byte[] { 2 }));
            Assert.Contains(InvalidVersionByte, ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWithTooLongEncryptionKeyId()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            string longTestPath = new string(Enumerable.Repeat('0', short.MaxValue).ToArray());

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(longTestPath, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificatePathLengthTooLong.Format(short.MaxValue), ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCertificatePathPartsExceedsThree()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("ExtraPart/CurrentUser/My/F00D", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificatePathPartsExceedsThree, ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCertificatePathHasUnsupportedLocation()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("UnsupportedLocation/My/F00D", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreLocation, ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCertificatePathHasUnsupportedName()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("CurrentUser/UnsupportedName/F00D", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreName, ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCertificatePathHasEmptyThumbprint()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("CurrentUser/My/", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(EmptySequence.Format("thumbprint"), ex.Message);
        }
    }
}