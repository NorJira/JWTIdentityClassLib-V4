using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class RefreshTokensByUserIdRequestDto
    {
        [Required]
        public string Id { get; set; }
    }
}
