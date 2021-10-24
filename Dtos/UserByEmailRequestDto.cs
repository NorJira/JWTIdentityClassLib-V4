using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class UserByEmailRequestDto
    {
        [EmailAddress]
        public string Email { get; set; }
    }
}
