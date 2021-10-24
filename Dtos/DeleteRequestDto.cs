using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class DeleteRequestDto
    {
        [Required]
        public string Id { get; set; }
    }
}
