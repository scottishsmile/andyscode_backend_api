
using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v1_0.User
{
    public class UserRegisterDto
    {
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 2)]
        public string UserName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {6} characters long.", MinimumLength = 6)]
        public string Password { get; set; }

        public string? GivenName { get; set; } = "empty"; // If field is not required we don't want it to be initialised as null or blank "".
        public string? FamilyName { get; set; } = "empty";

        public string? AddressNumber { get; set; } = "empty";                 // Could be 12A or Flat 2
        public string? AddressLine1 { get; set; } = "empty";
        public string? AddressLine2 { get; set; } = "empty";
        public string? City { get; set; } = "empty";
        public string? State { get; set; } = "empty";
        public string? Country { get; set; } = "empty";
        public string? PostCode { get; set; } = "empty";

        public string? Language { get; set; } = "English";                             // In case we ever translate the app.
        public string? Timezone { get; set; } = "(UTC+08:00) Perth";                    // In case we want to set reminders / notifications
        public bool Newsletter { get; set; } = false;          // Has user subscribed to our newsletter?

    }
}
