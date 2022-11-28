using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using SergeyREST;
using SergeyREST.Db;
using SergeyREST.Models;

namespace SergeyREST.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private List<User> GetUsers()
        {
            using (IDbConnection db = new SqlConnection("Server=DESKTOP-LBFBHMG; Database=Users; Trusted_Connection=True;"))
            {
                var query = "SELECT * FROM [Users]";
                return db.Query<User>(query).ToList();
            }
        }

        private void AddUser(User user)
        {
            var param = new DynamicParameters();
            param.Add("login", user.Login);
            param.Add("salt", user.Salt);
            param.Add("hash", user.Hash);

            using (IDbConnection db = new SqlConnection("Server=DESKTOP-LBFBHMG; Database=Users; Trusted_Connection=True;"))
            {
                var query = "INSERT INTO [Users] (login,salt,hash) VALUES (@login,@salt,@hash)";
                db.Query(query, param);
            }
        }
        [HttpPost("registrate")]
        public IActionResult Registrate(string login, string password)
        {
            List<User> users = GetUsers();
            
            //есть ли пользователь
            if (users.FirstOrDefault(x => x.Login.Equals(login)) != null)
                return BadRequest(400);
            try
            {
                //генерация соли
                byte[] random = new byte[30];
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(random);
                var salt = Convert.ToBase64String(random);

                User user = new User(login, salt, password.CreatePass(salt));
                AddUser(user);
                //users.SaveChanges();
                return Ok(201);
            }
            catch (Exception)
            {
                return BadRequest(400);
            }
        }

        [HttpPost("auth")]
        public IActionResult Auth(string login, string password)
        {
            List<User> users = GetUsers();
            //есть ли пользователь
            var temp = users.FirstOrDefault(x => x.Login.Equals(login));
            if (temp == null)
            {
                return BadRequest(401);
            }
            User user = new User(login, temp.Salt, password.CreatePass(temp.Salt));

            //валидация пользователя
            if (users.FirstOrDefault(x => user.Login.Equals(x.Login) && user.Hash.Equals(x.Hash)) != null)
            {

                //параметры jwt
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Login), //задал имя
                };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                //создание токена
                var start = DateTime.UtcNow;
                var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        notBefore: start,
                        claims: claimsIdentity.Claims,
                        expires: start.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));

                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt); //валидация токена

                var jwtRefresh = new JwtSecurityToken(
                    issuer: AuthOptions.REFRESH_ISSUER,
                    audience: AuthOptions.AUDIENCE_FOR_REFRESH,
                    notBefore: start,
                    claims: claimsIdentity.Claims.Where(item => item.Type == ClaimTypes.Name),
                    expires: start.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));

                string refreshEncodeJwt = new JwtSecurityTokenHandler().WriteToken(jwtRefresh); //валидация токена

                //отправка acces и refresh токена
                var responce = new
                {
                    access_token = encodedJwt,
                    request_token = refreshEncodeJwt
                };

                //добавили токены в куки
                HttpContext.Response.Cookies.Append("access_token", encodedJwt);
                HttpContext.Response.Cookies.Append("request_token", refreshEncodeJwt);

                //200 код
                return Ok(responce);
            }
            else
            {
                return BadRequest(401);
            }
        }

        [HttpPost("refresh")]
        public IActionResult Refresh()
        {
            //обновление токена
            try
            {
                string token = HttpContext.Request.Cookies.FirstOrDefault(item => item.Key.Equals("request_token")).Value;
                var jwtHandler = new JwtSecurityTokenHandler();
                var tokenValidParameters = new TokenValidationParameters()
                {
                    ValidIssuer = AuthOptions.REFRESH_ISSUER,
                    ValidAudience = AuthOptions.AUDIENCE_FOR_REFRESH,
                    IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
                var tokenContent = jwtHandler.ValidateToken(token, tokenValidParameters, out var _);
                if (tokenContent == null)
                {
                    throw new Exception();
                }
                var login = tokenContent.Claims.FirstOrDefault(item => item.Type.Equals(ClaimTypes.Name)).Value;
                
                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, login),
                };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                var start = DateTime.UtcNow;
                var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        notBefore: start,
                        claims: claimsIdentity.Claims,
                        expires: start.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                var jwtRefresh = new JwtSecurityToken(
                    issuer: AuthOptions.REFRESH_ISSUER,
                    audience: AuthOptions.AUDIENCE_FOR_REFRESH,
                    notBefore: start,
                    claims: claimsIdentity.Claims.Where(item => item.Type == ClaimTypes.Name),
                    expires: start.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                string refreshEncodeJwt = new JwtSecurityTokenHandler().WriteToken(jwtRefresh);

                HttpContext.Response.Cookies.Append("access_token", encodedJwt);
                HttpContext.Response.Cookies.Append("request_token", refreshEncodeJwt);
                return Ok(200);
            }
            catch (Exception )
            {
                return BadRequest(403);
            }
        }
    }
}
