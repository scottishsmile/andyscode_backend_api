using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v1_0.User
{
    public class AdminUpdateUserDto
    {
        // In .Net 6 if the field is non-nulable. No "?". then it is a REQUIRED Field!
        // https://stackoverflow.com/questions/72060349/form-field-is-required-even-if-not-defined-so

        // I don't like passing null or empty string to functions to signify the value hasn't changed
        // If the original value remains unchanged submit "unchanged".
        public string? Email { get; set; } = "unchanged";

        [Required]
        public string Id { get; set; }                             // User can change their username AND email address. So we need their Id to FIND them in the database.
        public string? NewUserName { get; set; } = "unchanged";             // If the user wants to change their username.
        public string? Password { get; set; } = "unchanged";
        public string? GivenName { get; set; } = "unchanged";
        public string? FamilyName { get; set; } = "unchanged";
        public string? Role { get; set; } = "unchanged";                                // Admin user may want to upgrade the user to Premium

        public string? AddressNumber { get; set; }                  // Could be 12A or Flat 2
        public string? AddressLine1 { get; set; }
        public string? AddressLine2 { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? PostCode { get; set; }

        public string? Language { get; set; } = "unchanged";                             // In case we ever translate the app.
        public string? Timezone { get; set; } = "unchanged";                    // In case we want to set reminders / notifications
        public bool AccountLocked { get; set; } = false;
    }
}
