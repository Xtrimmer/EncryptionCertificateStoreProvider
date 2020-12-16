using System;
using System.Collections.Generic;
using System.Linq;

using static Xtrimmer.KeyStoreProvider.Certificate.Properties.Resources;

namespace Xtrimmer.KeyStoreProvider.Certificate
{
    internal static class ArgumentValidationExtensions
    {
        internal static bool IsNull<T>(this T parameter)
        {
            return null == parameter;
        }

        internal static void ValidateNotNull<T>(this T parameter, string name)
        {
            if (parameter.IsNull())
            {
                throw new ArgumentNullException(string.Concat(name, " [", typeof(T), "]"));
            }
        }

        internal static void ValidateNotNullOrWhitespace(this string parameter, string name)
        {
            if (string.IsNullOrWhiteSpace(parameter))
            {
                throw new ArgumentException(NullOrWhitespaceString.Format(name));
            }
        }

        internal static void ValidateNotEmpty<T>(this IEnumerable<T> parameter, string name)
        {
            if (!parameter.Any())
            {
                throw new ArgumentException(EmptySequence.Format(name));
            }
        }

        internal static string Format(this string format, params object[] parameters)
        {
            return string.Format(format, parameters);
        }
    }
}
