using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace JWTIdentityClassLib.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }

        public bool AcceptTerms { get; set; }

        public int Role { get; set; }

        public string VerificationToken { get; set; }

        public DateTime? Verified { get; set; }

        public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;

        public string ResetToken { get; set; }

        public DateTime? ResetTokenExpires { get; set; }

        public DateTime? PasswordReset { get; set; }

        [MaxLength(1)]
        public string Status { get; set; }

        public DateTime Created { get; set; }

        public DateTime? Updated { get; set; }

        //---- Add Relationship (FK) to refreshtoken table
        public List<RefreshToken> RefreshTokens { get; set; } = new();

        public bool OwnsToken(string token)
        {
            return this.RefreshTokens?.Find(x => x.Token == token) != null;
        }
    }
}
