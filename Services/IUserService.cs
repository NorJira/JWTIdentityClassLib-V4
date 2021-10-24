using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using JWTIdentityClassLib.Dtos;

namespace JWTIdentityClassLib.Services
{
    public interface IUserService : IDisposable
    {
        Task<UserManagerResponseDto> RegisterUserAsync(RegisterRequestDto model, string origin);

        Task<UserManagerResponseDto> VerifyEmailAsync(string token);

        Task<AuthenticateResponseDto> AuthenticateAsync(AuthenticateRequestDto model, string ipAddress);

        Task<UserManagerResponseDto> ForgetPasswordAsync(ForgetPasswordRequestDto model, string origin);

        Task<UserManagerResponseDto> ResetPasswordAsync(ResetPasswordRequestDto model);

        Task<UserManagerResponseDto> ChangePasswordAsync(ChangePasswordRequestDto model);

        Task<UserManagerResponseDto> RevokeTokenAsync(string token, string ipAddress);

        Task<AuthenticateResponseDto> RefreshTokenAsync(string token, string ipAddress);

        Task<UserManagerResponseDto> ValidateResetTokenAsync(ValidateResetTokenRequestDto model);

        Task<IList<UserResponseDto>> GetUsersAsync();

        Task<UserResponseDto> GetUserByEmailAsync(UserByEmailRequestDto model);

        Task<IList<RefreshTokenResponseDto>> GetRefreshTokensByUserIdAsync(RefreshTokensByUserIdRequestDto model);

        //---------------------------

        Task<UserResponseDto> CreateAsync(RegisterRequestDto model);

        Task<UserResponseDto> UpdateAsync(UpdateRequestDto model);

        Task<UserManagerResponseDto> DeleteAsync(string Id);

        //Task<UserManagerResponseDto> LoginUserAsync(LoginRequestDto model);
    }

}
