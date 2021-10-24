using System;
using System.ComponentModel.DataAnnotations;

namespace JWTIdentityClassLib.Dtos
{
    public class RefreshTokenResponseDto
    {
        [Key]
        public int Id { get; set; }
        public string UserIdId { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public DateTime Created { get; set; }
        public string CreatedByIp { get; set; }
        public DateTime? Revoked { get; set; }
        public string RevokedByIp { get; set; }
        public string ReplacedByToken { get; set; }
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
