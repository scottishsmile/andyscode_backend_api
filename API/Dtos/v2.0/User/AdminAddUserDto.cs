using System.ComponentModel.DataAnnotations;

namespace API.Dtos.v2_0.User
{
    public class AdminAddUserDto
    {
        // In .Net 6 if the field is non-nulable. No "?". then it is a REQUIRED Field!
        // https://stackoverflow.com/questions/72060349/form-field-is-required-even-if-not-defined-so

        [EmailAddress]
        public string Email { get; set; } = "empty";                          // If field is not required we don't want it to be initialised as null or blank "".
        public string UserName { get; set; } = "empty";
        public string Password { get; set; } = "empty";
        public string? GivenName { get; set; } = "empty";
        public string? FamilyName { get; set; } = "empty";
        public string? Role { get; set; } = "AppBasic";                                // WHat role does the admin want them to be.

        public string? AddressNumber { get; set; } = "empty";                  // Could be 12A or Flat 2
        public string? AddressLine1 { get; set;  } = "empty";
        public string? AddressLine2 { get; set; } = "empty";
        public string? City { get; set; } = "empty";
        public string? State { get; set; } = "empty";
        public string? Country { get; set; } = "empty";
        public string? PostCode { get; set; } = "empty";

        public string? Language { get; set; } = "English";                             // In case we ever translate the app.
        public string? Timezone { get; set; } = "(UTC+08:00) Perth";                    // In case we want to set reminders / notifications
        public bool Newsletter { get; set; } = false;

        public bool EnableMFA { get; set; }
    }
}
