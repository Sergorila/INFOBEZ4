using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace SergeyREST
{
    public class AuthOptions
    {
        public const string ISSUER = "MyAuthServer"; // издатель токена
        public const string AUDIENCE = "MyAuthClient"; // потребитель токена
        const string KEY = "et0_s4miY_kruT0Y_kLy4_dly4_sh1frac11?";   // ключ для шифрации
        public const string REFRESH_ISSUER = "MyAuthServer";
        public const string AUDIENCE_FOR_REFRESH = "Refresh";
        public const int LIFETIME = 60; //час
        public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
    }
}
