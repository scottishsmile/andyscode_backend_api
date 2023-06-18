using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v1_0.User
{
    public class PasswordResetDto
    {

        public string UserName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {6} characters long.", MinimumLength = 6)]
        public string NewPassword { get; set; }

    }
}
