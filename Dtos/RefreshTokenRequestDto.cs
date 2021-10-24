using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class RefreshTokenRequestDto
    {
        [Required]
        public string Token { get; set; }
    }
}
