using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace SergeyREST.Models
{
    public class User
    {
        

        public User(string login, string salt, string hash)
        {
            Login = login;
            Salt = salt;
            Hash = hash;
        }

        [Key]
        public string Login { get; set; }

        private string _salt;
        public string Salt
        {
            get
            {
                return _salt;
            }
            set
            {
                _salt = value;
            }
        }

        private string _hash;
        public string Hash {
            get
            {
                return _hash;
            }
            set
            {
                _hash = value;
                ////хеширование
                //if (!String.IsNullOrEmpty(Login) && !String.IsNullOrEmpty(value))
                //{
                //    
                //}
                //else
                //{
                //    throw new ArgumentException();
                //}
            }
        }
    }
}
