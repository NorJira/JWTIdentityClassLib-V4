using JWTIdentityClassLib.Entities;
using JWTIdentityClassLib.Settings;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using JWTIdentityClassLib.Data;

namespace JWTIdentityClassLib.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JWTSettings _jwtSettings;
        private readonly UserManager<ApplicationUser> _userManager;

        public JwtMiddleware(RequestDelegate next, IOptions<JWTSettings> jwtSettings, UserManager<ApplicationUser> userManager)
        {
            _next = next;
            _jwtSettings = jwtSettings.Value;
            _userManager = userManager;
        }

        public async Task Invoke(HttpContext context, ApplicationDbContext dataContext)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
                await attachAccountToContext(context, dataContext, token);

            await _next(context);
        }

        private async Task attachAccountToContext(HttpContext context, ApplicationDbContext dataContext, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                //var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
                //var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);
                //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
                //tokenHandler.ValidateToken(token, new TokenValidationParameters
                //{
                //    ValidateIssuerSigningKey = true,
                //    IssuerSigningKey = key, //new SymmetricSecurityKey(key),  
                //    ValidateIssuer = false,
                //    ValidateAudience = false,
                //    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                //    ClockSkew = TimeSpan.Zero
                //}, out SecurityToken validatedToken);
                //--------------
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
                var validationParameters = new TokenValidationParameters()
                {
                    //IssuerSigningKey = key, //new BinarySecretSecurityToken(_key),
                    //ValidAudience = "",
                    //ValidIssuer = "",
                    //ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    //ClockSkew = TimeSpan.Zero
                };

                //var tokenHandler = new JwtSecurityTokenHandler();
                //SecurityToken validatedToken = null;

                var lifeTime = tokenHandler.ReadToken(token).ValidTo;
                var utcdt = DateTime.UtcNow;
                var localdt = DateTime.Now;

                var jwtToken = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);


                //-----------------
                //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
                //var tokenDescriptor = new SecurityTokenDescriptor
                //{
                //Subject = new ClaimsIdentity(new[] {
                //        new Claim("id", user.Id),
                //        new Claim("Email", user.Email),
                //        new Claim(ClaimTypes.NameIdentifier, user.Id)
                //}),
                //    Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenTTL),
                //    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
                //};
                //var tokenScript = tokenHandler.CreateToken(tokenDescriptor);
                //return tokenHandler.WriteToken(token);
                //var jwtToken = (JWTSecurityToken)tokenHandler.WriteToken(tokenScript);
                //-------------------
                //var jwtToken = (JwtSecurityToken)validatedToken;
                //var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);
                var userId = jwtToken.Claims.First(x => x.Type == "id").ToString().Split(" ").Last();

                // attach account to context on successful jwt validation
                //context.Items["User"] = await dataContext.Accounts.FindAsync(accountId);
                //ClaimsPrincipal existingUser = context.User;
                //context.Items["User"] = await _userManager.GetUserAsync(existingUser);
                var authenUser = await _userManager.FindByIdAsync(userId);
                context.Items["User"] = authenUser;
            }
            catch (Exception ex)
            {
                // do nothing if jwt validation fails
                // account is not attached to context so request won't have access to secure routes
                Console.WriteLine(ex.Message);
            }
        }
    }
}