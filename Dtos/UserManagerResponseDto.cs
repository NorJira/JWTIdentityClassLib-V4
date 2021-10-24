using System;
using System.Collections;
using System.Collections.Generic;

namespace JWTIdentityClassLib.Dtos
{
    public class UserManagerResponseDto
    {
        public string Message { get; set; }

        public bool isSuccess { get; set; }

        public IEnumerable<string> Errors { get; set; }

        public DateTime? ExpireDate { get; set; }
    }
}
