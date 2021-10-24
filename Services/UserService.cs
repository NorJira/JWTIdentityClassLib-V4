using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using JWTIdentityClassLib.Enum;
using JWTIdentityClassLib.Entities;
using JWTIdentityClassLib.Settings;
using JWTIdentityClassLib.Dtos;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using JWTIdentityClassLib.Data;

namespace JWTIdentityClassLib.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _userDbContext;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper;
        private readonly JWTSettings _jwtSettings;
        private readonly MailServiceSettings _emailSettings;
        private bool disposedValue;

        public UserService(UserManager<ApplicationUser> userManager,
            ApplicationDbContext userDbContext,
            IEmailService emailService,
            IMapper mapper,
            IOptions<JWTSettings> jwtSettings,
            IOptions<MailServiceSettings> emailSettings)
        {
            this._userManager = userManager;
            this._userDbContext = userDbContext;
            this._emailService = emailService;
            this._mapper = mapper;
            this._jwtSettings = jwtSettings.Value;
            this._emailSettings = emailSettings.Value;
        }

        public async Task<UserManagerResponseDto> RegisterUserAsync(RegisterRequestDto model, string origin)
        {
            // map model to new account object and set default value
            ApplicationUser applicationUser = _mapper.Map<ApplicationUser>(model);

            // search existing user
            //var dupUser = await _userManager.FindByNameAsync(model.UserName);
            //var dupUser = _userManager.Users.FirstOrDefault(x => (x.Email == model.Email) || (x.UserName == model.UserName));
            var dupEmail = await _userManager.FindByEmailAsync(model.Email);

            // validate
            if (dupEmail != null)        // Accounts.Any(x => x.Email == model.Email))
            {
                // send already registered error in email to prevent account enumeration
                sendAlreadyRegisteredEmail(model.Email, origin);
                //return new UserManagerResponseDto { Message = $"Cannot create user {model.Email}, Duplicate Email." };
                return new UserManagerResponseDto
                {
                    Message = $"Cannot create user {model.Email}, Duplicate Email.",
                    isSuccess = false
                };
            }

            // set other values of new user
            applicationUser.Role = model.Role == (int)Role.Admin ? (int)Role.Admin : (int)Role.User;
            applicationUser.Status = model.Status;
            applicationUser.Created = DateTime.UtcNow;
            // set verify token
            applicationUser.VerificationToken = randomTokenString();
            //applicationUser.VerificationToken = await _userManager.
            // hash password --NO NEED -usermanager will hash password when create
            //applicationUser.PasswordHash = BC.HashPassword(model.Password);

            // add to table
            var result = await _userManager.CreateAsync(applicationUser, model.Password);
            if (!result.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Error create user {model.Email}",
                    isSuccess = false,
                    Errors = result.Errors.AsEnumerable().Select(err => err.Description)
                };
            }
            // send email
            sendVerificationEmail(applicationUser, origin);

            // succeeded
            return new UserManagerResponseDto
            {
                Message = $"User {model.Email} created successfully!",
                isSuccess = true
            };
        }

        public async Task<UserManagerResponseDto> VerifyEmailAsync(string token)
        {
            var user = _userManager.Users.FirstOrDefault(x => x.VerificationToken == token);

            if (user == null)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Invalid token!!",
                    isSuccess = false,
                };
            }

            user.EmailConfirmed = true;
            user.Verified = DateTime.UtcNow;
            user.VerificationToken = null;

            var result = await _userManager.UpdateAsync(user);
            //
            if (!result.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Error verify user {user.Email}",
                    isSuccess = false,
                    Errors = result.Errors.AsEnumerable().Select(err => err.Description)
                };
            }
            // succeeded
            return new UserManagerResponseDto
            {
                Message = $"User {user.Email} verified successfully!",
                isSuccess = true
            };
        }

        public async Task<AuthenticateResponseDto> AuthenticateAsync(AuthenticateRequestDto model, string ipAddress)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !user.IsVerified)
                throw new ApplicationException("Email is incorrect or not verified");

            var validPassword = await _userManager.CheckPasswordAsync(user, model.Password);

            if (!validPassword)
                throw new ApplicationException("Password is incorrect");

            // authentication successful so generate jwt and refresh tokens
            var jwtToken = generateJwtToken(user);
            var refreshToken = generateRefreshToken(ipAddress);
            user.RefreshTokens.Add(refreshToken);

            // remove old refresh tokens from account
            removeOldRefreshTokens(user);

            // save changes to db
            await _userManager.UpdateAsync(user);

            var response = _mapper.Map<AuthenticateResponseDto>(user);
            response.JwtToken = jwtToken;
            response.RefreshToken = refreshToken.Token;
            return response;
        }

        public async Task<UserManagerResponseDto> ForgetPasswordAsync(ForgetPasswordRequestDto model, string origin)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            // always return ok response to prevent email enumeration
            //if (user == null) return;
            if (user == null)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Email {model.Email} not found!!",
                    isSuccess = false,
                };
            }

            // create reset token that expires after 1 day
            //user.ResetToken = randomTokenString();
            user.ResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            user.ResetTokenExpires = DateTime.Now.AddDays(1);

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Error update user {user.Email}",
                    isSuccess = false,
                    Errors = result.Errors.AsEnumerable().Select(err => err.Description)
                };
            }
            // send email
            sendPasswordResetEmail(user, origin);
            // succeeded
            return new UserManagerResponseDto
            {
                Message = $"Password Reset Email sent to User {user.Email} successfully!",
                isSuccess = true
            };
        }

        public async Task<UserManagerResponseDto> ResetPasswordAsync(ResetPasswordRequestDto model)
        {
            var user = _userManager.Users.FirstOrDefault(x =>
               x.ResetToken == model.Token &&
               x.ResetTokenExpires > DateTime.Now);
            if (user == null)
                return new UserManagerResponseDto
                {
                    Message = $"Token not found!!",
                    isSuccess = false
                    //Errors = validatePassword.Errors.AsEnumerable().Select(err => err.Description)
                };

            // validate new password
            var passwordValidator = new PasswordValidator<ApplicationUser>();

            var validatePassword = await passwordValidator.ValidateAsync(_userManager, null, model.Password);
            if (!validatePassword.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Invalid password!",
                    isSuccess = false,
                    Errors = validatePassword.Errors.AsEnumerable().Select(err => err.Description)
                };
            }
            // update password and remove reset token
            //user.PasswordHash = BC.HashPassword(model.Password);
            user.PasswordReset = DateTime.Now;
            //user.ResetToken = null;
            //user.ResetTokenExpires = null;
            //
            //await _userManager.ChangePasswordAsync(user, user.PasswordHash, model.Password);
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

            if (!result.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Cannot update password!",
                    isSuccess = false,
                    Errors = result.Errors.AsEnumerable().Select(err => err.Description)
                };
            }

            return new UserManagerResponseDto
            {
                Message = $"Update Password OK",
                isSuccess = true
                //Errors = result.Errors.AsEnumerable().Select(err => err.Description)
            };
        }

        public async Task<UserManagerResponseDto> ChangePasswordAsync(ChangePasswordRequestDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return new UserManagerResponseDto
                {
                    Message = $"User not found!!",
                    isSuccess = false
                    //Errors = validatePassword.Errors.AsEnumerable().Select(err => err.Description)
                };

            // validate new password
            var passwordValidator = new PasswordValidator<ApplicationUser>();

            var validatePassword = await passwordValidator.ValidateAsync(_userManager, null, model.NewPassword);
            if (!validatePassword.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Invalid new password!",
                    isSuccess = false,
                    Errors = validatePassword.Errors.AsEnumerable().Select(err => err.Description)
                };
            }
            // update password and remove reset token
            //user.PasswordHash = BC.HashPassword(model.Password);
            //user.PasswordReset = DateTime.UtcNow;
            ///user.ResetToken = null;
            //user.ResetTokenExpires = null;
            //
            //await _userManager.ChangePasswordAsync(user, user.PasswordHash, model.Password);
            user.ResetToken = null;
            user.ResetTokenExpires = null;
            user.Updated = DateTime.Now;
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            //
            if (!result.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Cannot Change password!",
                    isSuccess = false,
                    Errors = result.Errors.AsEnumerable().Select(err => err.Description)
                };
            }

            return new UserManagerResponseDto
            {
                Message = $"Change Password Done!",
                isSuccess = true
                //Errors = result.Errors.AsEnumerable().Select(err => err.Description)
            };
        }


        public async Task<UserManagerResponseDto> RevokeTokenAsync(string token, string ipAddress)
        {
            var (refreshToken, user) = getRefreshToken(token);

            // revoke token and save
            refreshToken.Revoked = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;
            // update
            var result = await _userManager.UpdateAsync(user);
            //_userDbContext.Update(refreshToken);
            //_userDbContext.SaveChanges();
            //
            if (!result.Succeeded)
            {
                return new UserManagerResponseDto
                {
                    Message = $"Error revoke token for user {user.Email}!",
                    isSuccess = false,
                    Errors = result.Errors.AsEnumerable().Select(err => err.Description)
                };
            }

            return new UserManagerResponseDto
            {
                Message = $"User {user.Email} has been revoke token successfully",
                isSuccess = true
                //Errors = result.Errors.AsEnumerable().Select(err => err.Description)
            };
        }

        public async Task<AuthenticateResponseDto> RefreshTokenAsync(string token, string ipAddress)
        {
            var (refreshToken, user) = getRefreshToken(token);

            // replace old refresh token with a new one and save
            var newRefreshToken = generateRefreshToken(ipAddress);
            refreshToken.Revoked = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = token;
            user.RefreshTokens.Add(newRefreshToken);

            removeOldRefreshTokens(user);

            //_context.Update(account);
            //_context.SaveChanges();
            var result = await _userManager.UpdateAsync(user);
            //
            if (!result.Succeeded) throw new ApplicationException($"Cannot update refresh token!");
            
            // generate new jwt
            var jwtToken = generateJwtToken(user);

            var response = _mapper.Map<AuthenticateResponseDto>(user);
            response.JwtToken = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        
        public async Task<UserManagerResponseDto> ValidateResetTokenAsync(ValidateResetTokenRequestDto model)
        {
            var user = _userManager.Users.FirstOrDefault(x =>
               x.ResetToken == model.Token &&
               x.ResetTokenExpires > DateTime.UtcNow);

            await Task.CompletedTask;

            if (user == null) return new UserManagerResponseDto { Message = $"Token not found!!" };
                //return new UserManagerResponseDto
                //{
                //    Message = $"Token not found!!",
                //    isSuccess = false
                //    //Errors = validatePassword.Errors.AsEnumerable().Select(err => err.Description)
                //};

            return new UserManagerResponseDto
            {
                Message = $"ResetToken has been validated successfully",
                isSuccess = true
                //Errors = result.Errors.AsEnumerable().Select(err => err.Description)
            };
        }

        public async Task<IList<UserResponseDto>> GetUsersAsync()
        {
            var users = _userManager.Users.AsEnumerable().ToList();
            await Task.CompletedTask;
            //
            if (users == null || users.Count() == 0) throw new ApplicationException("Users not found!");
            return _mapper.Map<IList<UserResponseDto>>(users);
        }

        public async Task<UserResponseDto> GetUserByEmailAsync(UserByEmailRequestDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            //
            if (user == null) throw new ApplicationException($"Email {model.Email} not found!");
            return _mapper.Map<UserResponseDto>(user);
        }

        public async Task<IList<RefreshTokenResponseDto>> GetRefreshTokensByUserIdAsync(RefreshTokensByUserIdRequestDto model)
        {
            var user = await _userManager.FindByIdAsync(model.Id);
            //
            if (user == null) throw new ApplicationException($"UserId not found!");
            if (user.RefreshTokens == null || user.RefreshTokens.Count() == 0)
                throw new ApplicationException("No RefreshToken found!");
            return _mapper.Map<IList<RefreshTokenResponseDto>>(user.RefreshTokens);
        }

        //public async Task<UserManagerResponseDto> LoginUserAsync(LoginRequestDto model)
        //{
        //    var existingUser = await _userManager.FindByEmailAsync(model.Email);

        //    if (existingUser == null)
        //        return new UserManagerResponseDto
        //        {
        //            Message = $"Cannot find user {model.Email}!!",
        //            isSuccess = false
        //        };

        //    var result = await _userManager.CheckPasswordAsync(existingUser, model.Password);

        //    if (!result)
        //        return new UserManagerResponseDto
        //        {
        //            Message = "Invalid password!!",
        //            isSuccess = false
        //        };

        //    var claims = new[]
        //    {
        //        new Claim("Email", model.Email),
        //        new Claim(ClaimTypes.NameIdentifier, existingUser.Id)
        //    };

        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));

        //    var token = new JwtSecurityToken(
        //        issuer: _jwtSettings.Issuer,
        //        audience: _jwtSettings.Audience,
        //        claims: claims,
        //        expires: DateTime.UtcNow.AddMinutes(5),
        //        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        //        );

        //    string tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        //    return new UserManagerResponseDto
        //    {
        //        Message = tokenString,
        //        isSuccess = true,
        //        ExpireDate = token.ValidTo
        //    };
        //}
        //------------------------------

        #region CRUD Functions

        public async Task<UserResponseDto> CreateAsync(RegisterRequestDto model)
        {
            // map model to new account object and set default value
            ApplicationUser newUser = _mapper.Map<ApplicationUser>(model);

            // search existing user
            //var dupUser = await _userManager.FindByNameAsync(model.UserName);
            //var dupUser = _userManager.Users.FirstOrDefault(x => (x.Email == model.Email) || (x.UserName == model.UserName));
            var dupEmail = await _userManager.FindByEmailAsync(model.Email);

            // validate
            if (dupEmail != null)        // Accounts.Any(x => x.Email == model.Email))
                throw new ApplicationException($"Cannot create user {model.Email}, Duplicate Email.");

            // set other values of new user
            newUser.Role = model.Role == (int)Role.Admin ? (int)Role.Admin : (int)Role.User;
            newUser.Created = DateTime.Now;
            // set verify token
            newUser.VerificationToken = randomTokenString();
            //newUser.VerificationToken = await _userManager.GeneratePasswordResetTokenAsync(newUser);
            // hash password --NO NEED -usermanager will hash password when create
            //applicationUser.PasswordHash = BC.HashPassword(model.Password);

            // add to table
            var result = await _userManager.CreateAsync(newUser, model.Password);
            if (!result.Succeeded)
                throw new ApplicationException($"Error create user {model.Email}.");

            // succeeded
            return _mapper.Map<UserResponseDto>(newUser);
        }

        public async Task<UserResponseDto> UpdateAsync(UpdateRequestDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null)
                throw new ApplicationException($"Not found user {model.UserName}");

            // copy model to user and save
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.AcceptTerms = model.AcceptTerms;
            user.Role = model.Role;
            user.Updated = DateTime.UtcNow;
            // save
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) throw new ApplicationException($"Error update user {model.UserName}");

            return _mapper.Map<UserResponseDto>(user);
        }

        public async Task<UserManagerResponseDto> DeleteAsync(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
                throw new ApplicationException($"Not found user Id");

            // save
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded) throw new ApplicationException($"Error delete user");

            return new UserManagerResponseDto
            {
                Message = "Delete Completed!",
                isSuccess = true
            };
            
        }

        #endregion

        //------------------------------

        #region Private Functions

        //private string generateJWTtoken(ApplicationUser user)
        //{
        //    var claims = new[]
        //    {
        //        new Claim("Id", user.Id),
        //        new Claim("Email", user.Email),
        //        new Claim(ClaimTypes.NameIdentifier, user.Id)
        //    };

        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AuthSetting:Key"]));

        //    var token = new JwtSecurityToken(
        //        issuer: _configuration["AuthSetting:Issuer"],
        //        audience: _configuration["AuthSetting:Audience"],
        //        claims: claims,
        //        expires: DateTime.UtcNow.AddMinutes(5),
        //        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        //        );

        //    return new JwtSecurityTokenHandler().WriteToken(token);
        //}

        private string generateJwtToken(ApplicationUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            //var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                    new Claim("id", user.Id.ToString()),
                    new Claim("Email", user.Email),
                    new Claim(ClaimTypes.NameIdentifier, user.Id)
                }),
                //Expires = DateTime.SpecifyKind(DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenTTL), DateTimeKind.Local),
                Expires = DateTime.Now.AddMinutes(_jwtSettings.AccessTokenTTL),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            //var tokenx = tokenHandler.WriteToken(token);
            //var validTo = tokenHandler.ReadToken(tokenx).ValidTo;
            //var validFrom = tokenHandler.ReadToken(tokenx).ValidFrom;
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken generateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                //UserIdId = user.Id,
                Token = randomTokenString(),
                //Token = await _userManager.GeneratePasswordResetTokenAsync(newUser);
                Expires = DateTime.Now.AddDays(_jwtSettings.RefreshTokenTTL),
                Created = DateTime.Now,
                CreatedByIp = ipAddress
            };
        }

        private void removeOldRefreshTokens(ApplicationUser user)
        {
            user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created.AddDays(_jwtSettings.RefreshTokenTTL) <= DateTime.Now);
        }

        private string randomTokenString()
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            // convert random bytes to hex string
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }

        private (RefreshToken, ApplicationUser) getRefreshToken(string token)
        {
            var user = _userManager.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null) throw new ApplicationException("Invalid token");
            //
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
            if (!refreshToken.IsActive) throw new ApplicationException("Invalid token");
            //
            return (refreshToken, user);
        }

       


        #endregion

        //------------------------------

        #region Send Notify Email

        private void sendVerificationEmail(ApplicationUser user, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var verifyUrl = $"{origin}/auth/verify-email?token={user.VerificationToken}";
                message = $@"<p>Please click the below link to verify your email address:</p>
                             <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to verify your email address with the <code>/auth/verify-email</code> api route:</p>
                             <p><code>{user.VerificationToken}</code></p>";
            }

            _emailService.Send(
                to: user.Email,
                subject: "Sign-up Verification API - Verify Email",
                html: $@"<h4>Verify Email</h4>
                         <p>Thanks for registering!</p>
                         {message}"
            );
        }

        private void sendAlreadyRegisteredEmail(string email, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
                message = $@"<p>If you don't know your password please visit the <a href=""{origin}/auth/forgot-password"">forgot password</a> page.</p>";
            else
                message = "<p>If you don't know your password you can reset it via the <code>/auth/forgot-password</code> api route.</p>";

            _emailService.Send(
                to: email,
                subject: "Sign-up Verification API - Email Already Registered",
                html: $@"<h4>Email Already Registered</h4>
                         <p>Your email <strong>{email}</strong> is already registered.</p>
                         {message}"
            );
        }

        private void sendPasswordResetEmail(ApplicationUser user, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/auth/reset-password?token={user.ResetToken}";
                message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                             <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/auth/reset-password</code> api route:</p>
                             <p><code>{user.ResetToken}</code></p>";
            }

            _emailService.Send(
                to: user.Email,
                subject: "Sign-up Verification API - Reset Password",
                html: $@"<h4>Reset Password Email</h4>
                         {message}"
            );
        }


        #endregion

        #region Dispose

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                    _userDbContext.Dispose();
                    _userManager.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~UserService()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
