using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.Globalization;

namespace API.Models
{
    public class AppUser : IdentityUser
    {
        // The normal IdentityUser model has ID, UserName, Email, EmailConfirmed, PasswordHash
        // Lets add a couple custom fields.

        // All these fields also have to be in Factories > AppUserClaimsPrincipalFactory
        // So that they are added to the JWT token and our API can then see them.

        [MaxLength(300)]
        public string? GivenName { get; set; }

        [MaxLength(300)]
        public string? FamilyName { get; set; }


        [MaxLength(300)]
        public string? AddressNumber { get; set; }                  // Could be 12A or Flat 2
        [MaxLength(300)]
        public string? AddressLine1 { get; set; }
        [MaxLength(300)]
        public string? AddressLine2 { get; set; }
        [MaxLength(300)]
        public string? City { get; set; }
        [MaxLength(300)]
        public string? State { get; set; }
        [MaxLength(300)]
        public string? Country { get; set; } = "Australia";     // List of Country Codes - https://gist.github.com/Venoli/685c5bb24ba8170a7b22f46089d77224  & http://www.codedigest.com/CodeDigest/207-Get-All-Language-Country-Code-List-for-all-Culture-in-C---ASP-Net.aspx
        [MaxLength(300)]
        public string? PostCode { get; set; }


        [MaxLength(300)]
        public string? Language { get; set; } = "English";                             // In case we ever translate the app.

        // TimeZoneInfo
        // https://learn.microsoft.com/en-us/dotnet/api/system.timezoneinfo?view=net-7.0
        // List of TimeZone Info Ids - https://stackoverflow.com/questions/7908343/list-of-timezone-ids-for-use-with-findtimezonebyid-in-c
        [MaxLength(300)]
        public string? Timezone { get; set; } = "(UTC+08:00) Perth";                   // In case we want to set reminders / notifications

        public bool Newsletter { get; set; } = true;                                    // Checkbox for mailchimp newsletter subscription. True = subscribe to newsletter.

        public DateTime LastConfirmEmailSent { get; set; } = DateTime.MinValue;           // To prevent spammers being able to keep sending confirmation emails lets track the last time one was sent

        public DateTime LastPasswordResetEmailSent  { get; set; } = DateTime.MinValue;    // To prevent spammers being able to keep sending password reset emails lets track the last time one was sent

        public string? UnconfirmedEmail { get; set; }                                   // User may want to change their email address, we need to keep a record of it so that we ONLY update the main email once the new email has been confirmed. So user can't enter the wrong email and lock themselves out.

        public virtual ICollection<RefreshTokenTable> RefreshTokenTable { get; set; }

        public virtual ICollection<MfaCodeTable> MfaCodeTable { get; set; }

        public virtual ICollection<MfaTokenTable> MfaTokenTable { get; set; }

        public DateTime? LastLogin { get; set; } = DateTime.UtcNow;                  // Date of user's last login.

        public DateTime? RegistrationDate { get; set; } = DateTime.UtcNow;           // Date the user registered.

        public bool EnableMFA { get; set; } = false;                                // Multi Factor Auth enabled for the user's account

    }
}
