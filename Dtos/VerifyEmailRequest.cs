using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
