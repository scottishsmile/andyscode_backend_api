using System.ComponentModel.DataAnnotations;
using System.Security.Policy;

namespace API.Dtos.v2_0.User
{
    public class LoginResponseDto
    {
        // This is our reply back to the React client after a successful login.
        // React will need to use the Username and Role for some of it's routing decisions.

        // In .Net 6 if the field is non-nulable. No "?". then it is a REQUIRED Field!
        // https://stackoverflow.com/questions/72060349/form-field-is-required-even-if-not-defined-so

        public string? AccessToken { get; set; }                // Access Token
        public DateTime? AccessTokenExpiry { get; set; }
        public string? RefreshToken { get; set; }               // Refresh Token
        public DateTime? RefreshTokenExpiry { get; set; }

        public string? Id { get; set; }

        [EmailAddress]
        public string? Email { get; set; }
        public string? Username { get; set; }
        public IList<string>? Roles { get; set; }       // User roles are already in the JWT token. Maybe remove this?

        public bool? MFA_Enabled { get; set; }

        public string? MfaToken { get; set; }               // Multi-factor Auth Token. Used to then allow user to submit MFA code.
        public DateTime? MfaTokenExpiry { get; set; }
    }
}
