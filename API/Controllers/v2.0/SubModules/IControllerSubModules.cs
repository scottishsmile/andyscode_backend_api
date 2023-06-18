using API.Dtos.v2_0.User;
using API.Models;
using API.Models.v2_0;
using System.Threading.Tasks;

namespace API.Controllers.v2_0.SubModules
{
    public interface IControllerSubModulesV2
    {
        Task<AppUser> GetUserByEmailOrUserName(string usernameOrEmail);

        Task<AppUser> GetUserByEmailOrUserNameAndVerifyPassword(UserLoginDto credentials);

        (string token, DateTime DateTokenExpires) GenerateAccessToken(AppUser user, IList<string> userRoles);

        Task<RefreshTokenTable> GenerateRefreshToken(AppUser user, string? refreshToken = null);

        bool ValidateRefreshToken(string refreshToken);

        Task<bool> RefreshTokenIsCurrent(string token);                                     // Check refresh token expiry date

        Task<bool> RefreshTokenIsAssignedToUser(string token, string userId);               // Check refresh token is assigned to the specified user

        Task<bool> RefreshTokenPruning(AppUser user);                                       // Delete Expired Refresh Tokens

        Task<bool> SendConfirmEmail(AppUser user);

        Task<bool> SendChangeEmailConfirmation(AppUser user, string newEmail);              // Users can only send an email every hour, prevents spam. Spam bot may sign up as someone else's email and request 100s of confirm emails.

        Task<bool> AdminSendChangeEmailConfirmation(AppUser user, string newEmail);         // Admin users need to send emails immediately, no hold timer.

        Task<bool> SendPasswordResetEmail(AppUser user);                                    // Users can only send an email every hour, prevents spam. Spam bot may sign up as someone else's email and request 100s of password reset emails.

        Task<bool> AdminSendPasswordResetEmail(AppUser user);

        Task<bool> ValidateEmailAddress(string email);

        bool IsBase64String(string base64);                                                 // Check if Token is in BASE64 format.

        Task<bool> RecordLastLogin(AppUser user);

        Task<MfaTokenTable> GenerateMfaToken(AppUser user, string? mfaToken = null);

        bool ValidateMfaToken(string token);

        Task<bool> MfaTokenIsCurrent(string token);                                     // Check MFA token expiry date

        Task<bool> MfaTokenIsAssignedToUser(string token, string userId);               // Check MFA token is assigned to the specified user

        Task<bool> MfaTokenPruning(AppUser user);

    }
}
