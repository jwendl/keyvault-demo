using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KeyVaultExample.Extensions
{
    public static class IEnumerableExtensions
    {
        public static string ToDictionaryKey(this IEnumerable<string> scopes)
        {
            var stringBuilder = new StringBuilder();
            foreach (var scope in scopes)
            {
                stringBuilder.Append(scope);
                if (scope != scopes.Last())
                {
                    stringBuilder.Append(':');
                }
            }
            using (var md5Hash = MD5.Create())
            {
                return GetMd5Hash(md5Hash, stringBuilder.ToString());
            }
        }

        private static string GetMd5Hash(MD5 md5Hash, string input)
        {
            var data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            var stringBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                stringBuilder.Append(data[i].ToString("x2"));
            }

            return stringBuilder.ToString();
        }
    }
}
