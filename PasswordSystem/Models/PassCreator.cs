using System;
using System.Security.Cryptography;
using System.Text;

namespace SergeyREST.Models
{
    public static class PassCreator
    {
        public static string CreatePass(this string value, string salt)
        {
            using (SHA512 crypt = new SHA512Managed())
            {
                return Convert.ToBase64String(crypt.ComputeHash(Encoding.UTF8.GetBytes(value + salt)));
            }
        }
    }
}
