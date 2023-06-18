using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v2_0.User
{
    public class ForgotPasswordDto
    {
        [EmailAddress]
        public string Email { get; set; }
    }
}
