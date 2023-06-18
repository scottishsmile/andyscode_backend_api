using API.Dtos.v2_0;
using API.Models;

namespace API.Services.v2_0.MyMFA
{
    public interface IMyMFA
    {
        Task<bool> SendCode(AppUser user);                  // Generates random 8 digit code for MFA and saves the Date it was created and expiry date to database.

        Task<bool> ConfirmCode(AppUser user, string code);         // Confirms code matches the user's saved code.

        Task<bool> CodePruning(AppUser user);                   // Removes any codes in the database with expiry dates older than 1 hour.

    }
}
