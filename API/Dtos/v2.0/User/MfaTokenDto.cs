using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v2_0.User
{
    public class MfaTokenDto
    {

        [Required]
        public string MfaToken { get; set; }

        [Required]
        public string MfaCode { get; set; }

        [Required]
        public string UserName { get; set; }
    }
}
