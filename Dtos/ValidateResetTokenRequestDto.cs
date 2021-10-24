using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class ValidateResetTokenRequestDto
    {
        [Required]
        public string Token { get; set; }
    }
}
