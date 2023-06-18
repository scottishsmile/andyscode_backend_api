﻿using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v2_0.User
{
    public class RefreshTokenDto
    {
        [Required]
        public string RefreshToken { get; set; }

        [Required]
        public string UserName { get; set; }
    }
}
