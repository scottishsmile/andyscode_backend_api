using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v2_0.User
{
    public class PremiumUpgradeDto
    {
        [Required]
        public string Id { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 2)]
        public string UserName { get; set; }


    }
}
