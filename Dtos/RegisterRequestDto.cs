using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class RegisterRequestDto
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        [MaxLength(20), MinLength(6)]
        public string Password { get; set; }

        [Required]
        [MaxLength(20), MinLength(6)]
        [Compare("Password", ErrorMessage = "Password and Confirm Password not match!!")]
        public string ConfirmPassword { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Range(typeof(bool), "true", "true")]
        public bool AcceptTerms { get; set; }

        [Required]
        public int Role { get; set; }

        [Required]
        public string Status { get; set; }

    }
}
