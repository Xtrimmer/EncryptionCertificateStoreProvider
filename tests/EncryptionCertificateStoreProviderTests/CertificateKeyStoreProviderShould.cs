using Microsoft.Data.Encryption.Cryptography;
using System;
using Xunit;
using Xtrimmer.KeyStoreProvider.Certificate;
using static Microsoft.Data.Encryption.Cryptography.KeyEncryptionKeyAlgorithm;
using System.Linq;

using static Xtrimmer.KeyStoreProvider.Certificate.Properties.Resources;
using System.Security.Cryptography.X509Certificates;

namespace Xtrimmer.EncryptionCertificateStoreProviderTests
{
    public sealed class CertificateKeyStoreProviderShould
    {
        [Theory]
        [InlineData(256)]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public void WrapAndUnwrapKeyCorrectly(int keySizeInBits)
        {
            string path = null;
            byte[] plaintextKey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate(
                    subject: $"{nameof(ThrowWhenUnwrapKeyCalledWhenSignatureIsInvalid)}_TestCertificate",
                    storeLocation: StoreLocation.CurrentUser,
                    keySizeInBits: keySizeInBits
                );

                byte[] wrappedKey = provider.WrapKey(path, RSA_OAEP, plaintextKey);
                byte[] unwrappedPlaintextKey = provider.UnwrapKey(path, RSA_OAEP, wrappedKey);

                Assert.Equal(expected: plaintextKey, actual: unwrappedPlaintextKey);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void SignAndVerifyCorrectly(bool allowEnclaveComputations)
        {
            string path = null;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate(
                    subject: $"{nameof(ThrowWhenUnwrapKeyCalledWhenSignatureIsInvalid)}_TestCertificate",
                    storeLocation: StoreLocation.CurrentUser
                );

                byte[] signature = provider.Sign(path, allowEnclaveComputations);
                bool verification = provider.Verify(path, allowEnclaveComputations, signature);

                Assert.True(verification);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        /// <summary>
        /// This test requires elevated privelages to access the StoreLocation.LocalMachine.
        /// Without, it will fail with "CryptographicException: Access denied."
        /// </summary>
        [Fact]
        public void WorkWithTwoPartCertificatePath()
        {
            string path = null;
            byte[] plaintextKey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = string.Join("/", TestHelpers.CreateCertificate(
                    subject: $"{nameof(WorkWithTwoPartCertificatePath)}_TestCertificate",
                    storeLocation: StoreLocation.LocalMachine,
                    keySizeInBits: 2048
                ).Split('/').Skip(1));

                byte[] wrappedKey = provider.WrapKey(path, RSA_OAEP, plaintextKey);
                byte[] unwrappedPlaintextKey = provider.UnwrapKey(path, RSA_OAEP, wrappedKey);

                Assert.Equal(expected: plaintextKey, actual: unwrappedPlaintextKey);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        #region UnwrapKey Error Condition Tests

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

        [Theory]
        [DataAttributes.UnsupportedCertificatePathData]
        public void ThrowWhenUnwrapKeyCalledWhenCertificatePathHasUnsupportedName(string path)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(path, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreName, ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCertificatePathHasEmptyThumbprint()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey("CurrentUser/My/", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(EmptySequence.Format("thumbprint"), ex.Message);
        }

        [Theory]
        [InlineData(StoreLocation.CurrentUser, StoreName.My)]
        [InlineData(StoreLocation.LocalMachine, StoreName.My)]
        public void ThrowWhenUnwrapKeyCalledWhenCertificateDoesNotExist(StoreLocation location, StoreName name)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            const string missingThumbprint = "F00D";

            Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey($"{location}/{name}/{missingThumbprint}", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificateNotFound.Format(missingThumbprint, name, location), ex.Message);
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCertificateHasNoPrivateKey()
        {
            string path = null;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate($"{nameof(ThrowWhenUnwrapKeyCalledWhenCertificateHasNoPrivateKey)}_TestCertificate", StoreLocation.CurrentUser, hasPrivateKey: false);

                Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(path, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
                Assert.Contains(CertificateWithoutPrivateKey.Format(path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenCiphertextSizeDoesNotMatchWhatIsExpected()
        {
            string path = null;
            int certificateKeySizeInBits = 2048;
            int certificateKeySizeInBytes = certificateKeySizeInBits / 8;
            short invalidCiphertextSize = 1;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate(
                    subject: $"{nameof(ThrowWhenUnwrapKeyCalledWhenCiphertextSizeDoesNotMatchWhatIsExpected)}_TestCertificate", 
                    storeLocation: StoreLocation.CurrentUser,
                    keySizeInBits: certificateKeySizeInBits
                );
                byte[] invalidSizedKey = provider
                    .WrapKey(path, RSA_OAEP, Enumerable.Repeat((byte)1, 32).ToArray())
                    .ChangeCiphertextLengthParameter(targetCiphertextSize: invalidCiphertextSize);

                Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(path, RSA_OAEP, invalidSizedKey));
                Assert.Contains(UnexpectedCiphertextLength.Format(invalidCiphertextSize, certificateKeySizeInBytes, path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenSignatureSizeDoesNotMatchWhatIsExpected()
        {
            string path = null;
            int certificateKeySizeInBits = 2048;
            int certificateKeySizeInBytes = certificateKeySizeInBits / 8;
            short invalidSignatureSize = 1;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate(
                    subject: $"{nameof(ThrowWhenUnwrapKeyCalledWhenSignatureSizeDoesNotMatchWhatIsExpected)}_TestCertificate",
                    storeLocation: StoreLocation.CurrentUser,
                    keySizeInBits: certificateKeySizeInBits
                );
                byte[] invalidSizedSignature = provider
                    .WrapKey(path, RSA_OAEP, Enumerable.Repeat((byte)1, 32).ToArray())
                    .ChangeSignatureLength(targetSignatureSize: invalidSignatureSize);

                Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(path, RSA_OAEP, invalidSizedSignature));
                Assert.Contains(UnexpectedSignatureLength.Format(invalidSignatureSize, certificateKeySizeInBytes, path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        [Fact]
        public void ThrowWhenUnwrapKeyCalledWhenSignatureIsInvalid()
        {
            string path = null;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate(
                    subject: $"{nameof(ThrowWhenUnwrapKeyCalledWhenSignatureIsInvalid)}_TestCertificate",
                    storeLocation: StoreLocation.CurrentUser
                );
                byte[] encryptedKeyWithInvalidSignature = provider
                    .WrapKey(path, RSA_OAEP, Enumerable.Repeat((byte)1, 32).ToArray())
                    .InvalidateSignature();

                Exception ex = Assert.Throws<ArgumentException>(() => provider.UnwrapKey(path, RSA_OAEP, encryptedKeyWithInvalidSignature));
                Assert.Contains(InvalidSignature.Format(path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        #endregion

        #region WrapKey Error Condition Tests

        [Theory]
        [DataAttributes.NullOrWhitespaceData]
        public void ThrowWhenWrapKeyCalledWithNullOrWhitespaceEncryptionKeyId(string encryptionKeyId)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey(encryptionKeyId, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(NullOrWhitespaceString.Format("encryptionKeyId"), ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWithNullKey()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentNullException>(() => provider.WrapKey("testPath", RSA_OAEP, null));
            Assert.Contains(NullArgument.Format("key", typeof(byte[])), ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWithKey()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey("testPath", RSA_OAEP, new byte[] { }));
            Assert.Contains(EmptySequence.Format("key"), ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWithTooLongEncryptionKeyId()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            string longTestPath = new string(Enumerable.Repeat('0', short.MaxValue).ToArray());

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey(longTestPath, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificatePathLengthTooLong.Format(short.MaxValue), ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWhenCertificatePathPartsExceedsThree()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey("ExtraPart/CurrentUser/My/F00D", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificatePathPartsExceedsThree, ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWhenCertificatePathHasUnsupportedLocation()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey("UnsupportedLocation/My/F00D", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreLocation, ex.Message);
        }

        [Theory]
        [DataAttributes.UnsupportedCertificatePathData]
        public void ThrowWhenWrapKeyCalledWhenCertificatePathHasUnsupportedName(string path)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey(path, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreName, ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWhenCertificatePathHasEmptyThumbprint()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey("CurrentUser/My/", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(EmptySequence.Format("thumbprint"), ex.Message);
        }

        [Theory]
        [InlineData(StoreLocation.CurrentUser, StoreName.My)]
        [InlineData(StoreLocation.LocalMachine, StoreName.My)]
        public void ThrowWhenWrapKeyCalledWhenCertificateDoesNotExist(StoreLocation location, StoreName name)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            const string missingThumbprint = "F00D";

            Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey($"{location}/{name}/{missingThumbprint}", RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificateNotFound.Format(missingThumbprint, name, location), ex.Message);
        }

        [Fact]
        public void ThrowWhenWrapKeyCalledWhenCertificateHasNoPrivateKey()
        {
            string path = null;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate($"{nameof(ThrowWhenUnwrapKeyCalledWhenCertificateHasNoPrivateKey)}_TestCertificate", StoreLocation.CurrentUser, hasPrivateKey: false);

                Exception ex = Assert.Throws<ArgumentException>(() => provider.WrapKey(path, RSA_OAEP, new byte[] { 1, 2, 3, 4, 5 }));
                Assert.Contains(CertificateWithoutPrivateKey.Format(path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        #endregion

        #region Sign Error Condition Tests

        [Theory]
        [DataAttributes.NullOrWhitespaceData]
        public void ThrowWhenSignCalledWithNullOrWhitespaceEncryptionKeyId(string encryptionKeyId)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign(encryptionKeyId, allowEnclaveComputations: true));
            Assert.Contains(NullOrWhitespaceString.Format("encryptionKeyId"), ex.Message);
        }

        [Fact]
        public void ThrowWhenSignCalledWithTooLongEncryptionKeyId()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            string longTestPath = new string(Enumerable.Repeat('0', short.MaxValue).ToArray());

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign(longTestPath, allowEnclaveComputations: true));
            Assert.Contains(CertificatePathLengthTooLong.Format(short.MaxValue), ex.Message);
        }

        [Fact]
        public void ThrowWhenSignCalledWhenCertificatePathPartsExceedsThree()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign("ExtraPart/CurrentUser/My/F00D", allowEnclaveComputations: true));
            Assert.Contains(CertificatePathPartsExceedsThree, ex.Message);
        }

        [Fact]
        public void ThrowWhenSignCalledWhenCertificatePathHasUnsupportedLocation()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign("UnsupportedLocation/My/F00D", allowEnclaveComputations: true));
            Assert.Contains(UnsupportedCertificateStoreLocation, ex.Message);
        }

        [Theory]
        [DataAttributes.UnsupportedCertificatePathData]
        public void ThrowWhenSignCalledWhenCertificatePathHasUnsupportedName(string path)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign(path, allowEnclaveComputations: true));
            Assert.Contains(UnsupportedCertificateStoreName, ex.Message);
        }

        [Fact]
        public void ThrowWhenSignCalledWhenCertificatePathHasEmptyThumbprint()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign("CurrentUser/My/", allowEnclaveComputations: true));
            Assert.Contains(EmptySequence.Format("thumbprint"), ex.Message);
        }

        [Theory]
        [InlineData(StoreLocation.CurrentUser, StoreName.My)]
        [InlineData(StoreLocation.LocalMachine, StoreName.My)]
        public void ThrowWhenSignCalledWhenCertificateDoesNotExist(StoreLocation location, StoreName name)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            const string missingThumbprint = "F00D";

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign($"{location}/{name}/{missingThumbprint}", allowEnclaveComputations: true));
            Assert.Contains(CertificateNotFound.Format(missingThumbprint, name, location), ex.Message);
        }

        [Fact]
        public void ThrowWhenSignCalledWhenCertificateHasNoPrivateKey()
        {
            string path = null;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate($"{nameof(ThrowWhenUnwrapKeyCalledWhenCertificateHasNoPrivateKey)}_TestCertificate", StoreLocation.CurrentUser, hasPrivateKey: false);

                Exception ex = Assert.Throws<ArgumentException>(() => provider.Sign(path, allowEnclaveComputations: true));
                Assert.Contains(CertificateWithoutPrivateKey.Format(path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        #endregion

        #region Verify Error Condition Tests

        [Theory]
        [DataAttributes.NullOrWhitespaceData]
        public void ThrowWhenVerifyCalledWithNullOrWhitespaceEncryptionKeyId(string encryptionKeyId)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify(encryptionKeyId, allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(NullOrWhitespaceString.Format("encryptionKeyId"), ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWithTooLongEncryptionKeyId()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            string longTestPath = new string(Enumerable.Repeat('0', short.MaxValue).ToArray());

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify(longTestPath, allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificatePathLengthTooLong.Format(short.MaxValue), ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWithNullSignature()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentNullException>(() => provider.Verify("testPath", allowEnclaveComputations: true, null));
            Assert.Contains(NullArgument.Format("signature", typeof(byte[])), ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWithEmptySignature()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify("testPath", allowEnclaveComputations: true, new byte[] { }));
            Assert.Contains(EmptySequence.Format("signature"), ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWhenCertificatePathPartsExceedsThree()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify("ExtraPart/CurrentUser/My/F00D", allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificatePathPartsExceedsThree, ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWhenCertificatePathHasUnsupportedLocation()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify("UnsupportedLocation/My/F00D", allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreLocation, ex.Message);
        }

        [Theory]
        [DataAttributes.UnsupportedCertificatePathData]
        public void ThrowWhenVerifyCalledWhenCertificatePathHasUnsupportedName(string path)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify(path, allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(UnsupportedCertificateStoreName, ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWhenCertificatePathHasEmptyThumbprint()
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify("CurrentUser/My/", allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(EmptySequence.Format("thumbprint"), ex.Message);
        }

        [Theory]
        [InlineData(StoreLocation.CurrentUser, StoreName.My)]
        [InlineData(StoreLocation.LocalMachine, StoreName.My)]
        public void ThrowWhenVerifyCalledWhenCertificateDoesNotExist(StoreLocation location, StoreName name)
        {
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();
            const string missingThumbprint = "F00D";

            Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify($"{location}/{name}/{missingThumbprint}", allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
            Assert.Contains(CertificateNotFound.Format(missingThumbprint, name, location), ex.Message);
        }

        [Fact]
        public void ThrowWhenVerifyCalledWhenCertificateHasNoPrivateKey()
        {
            string path = null;
            EncryptionKeyStoreProvider provider = new CertificateKeyStoreProvider();

            try
            {
                path = TestHelpers.CreateCertificate($"{nameof(ThrowWhenUnwrapKeyCalledWhenCertificateHasNoPrivateKey)}_TestCertificate", StoreLocation.CurrentUser, hasPrivateKey: false);

                Exception ex = Assert.Throws<ArgumentException>(() => provider.Verify(path, allowEnclaveComputations: true, new byte[] { 1, 2, 3, 4, 5 }));
                Assert.Contains(CertificateWithoutPrivateKey.Format(path), ex.Message);
            }
            finally
            {
                TestHelpers.RemoveCertificate(path);
            }
        }

        #endregion
    }
}