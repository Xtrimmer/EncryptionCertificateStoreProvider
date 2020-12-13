using System.Collections.Generic;
using System.Reflection;
using Xunit.Sdk;

namespace Xtrimmer.EncryptionCertificateStoreProviderTests
{
    public static class DataAttributes
    {
        public class NullOrWhitespaceDataAttribute : DataAttribute
        {
            public override IEnumerable<object[]> GetData(MethodInfo testMethod)
            {
                yield return new object[] { null };
                yield return new object[] { "" };
                yield return new object[] { "\n" };
                yield return new object[] { "\t" };
                yield return new object[] { "\r" };
                yield return new object[] { "     " };
            }
        }
    }
}
