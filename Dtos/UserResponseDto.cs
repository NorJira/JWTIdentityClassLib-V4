﻿using System;
namespace JWTIdentityClassLib.Dtos
{
    public class UserResponseDto
    {
		public string Id { get; set; }

		public string UserName { get; set; }

		public string Email { get; set; }

		public string EmailConfirmed { get; set; }

		public string FirstName { get; set; }

		public string LastName { get; set; }

		public int Role { get; set; }

		public string Status { get; set; }

		public DateTime Created { get; set; }

		public DateTime? Updated { get; set; }

		public bool IsVerified { get; set; }

		public string JwtToken { get; set; }

	}
}
