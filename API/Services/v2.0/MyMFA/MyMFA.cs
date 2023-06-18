using API.Models;
using API.Models.v2_0;
using API.Dtos.v2_0;
using API.Services.v2_0.Newsletter;
using Newtonsoft.Json.Linq;
using sib_api_v3_sdk.Api;
using sib_api_v3_sdk.Model;
using Microsoft.EntityFrameworkCore;
using API.Data;
using Microsoft.Extensions.Options;
using API.Migrations;
using API.Services.v2_0.EmailService;
using System.Collections.Generic;

namespace API.Services.v2_0.MyMFA
{
    public class MyMFA : IMyMFA
    {
        private readonly ILogger<MyMFA> _logger;
        private readonly AppDbContext _context;
        private readonly IOptions<MyMFASettings> _MyMFASettings;
        private readonly IOptions<EmailConfigV2> _emailConfig;                 // Get appsettings.json configs
        private readonly IEmailServiceV2 _email;

        public MyMFA(ILogger<MyMFA> logger, AppDbContext context, IOptions<MyMFASettings> MyMFASettings, IOptions<EmailConfigV2> emailConfig, IEmailServiceV2 email)
        {
            _logger = logger;
            _context = context;
            _MyMFASettings = MyMFASettings;
            _emailConfig = emailConfig;
            _email = email;

        }

        public async Task<bool> SendCode(AppUser user)
        {
            try
            {
                // Generate Random 6 digit Code
                // You can't get leading zeros with integers, needs to be a string.
                Random r = new Random();
                string code = r.Next(0, _MyMFASettings.Value.MFA_CodeLength).ToString("D6");

                // When will the code expire?
                var dateCodeExpires = DateTime.UtcNow.AddMinutes(_MyMFASettings.Value.MFACodeExpiryTimeInMinutes);

                // Save code, date it was created and the user it is assigned to
                var newCode = new MfaCodeTable
                {
                    UserId = user.Id,
                    MFA_Code = code,
                    DateCodeIssued = DateTime.UtcNow,
                    DateCodeExpires = dateCodeExpires
                };

                var addToTable = await _context.MfaCodeTable.AddAsync(newCode);

                // Save changes to database
                var save = await _context.SaveChangesAsync();

                // Send email with the code to the user
                string siteTitle = _emailConfig.Value.SiteTitle;
                string siteName = _emailConfig.Value.SiteName;
                int codeExpires = _MyMFASettings.Value.MFACodeExpiryTimeInMinutes;
                string loginLink = _emailConfig.Value.FrontEndWebsiteUrl;
                string subject = $@"{siteTitle} - Login Code";
                string message = $@"<p>Your login code is: {code} </p><p>It expires in {codeExpires} minutes.</p><p>Login: <a href='{loginLink}'>Login</a><p>";

                _email.SendEmail(user.Email, subject, message);

                // Signal that the code was created successfully.
                return true;


            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in MyMFA.GenerateCode - {0}", ex.Message);

                // Signal that the code was not created.
                return false;

            }

        }


        public async Task<bool> ConfirmCode(AppUser user, string code)
        {
            var serviceResponse = new ServiceResponse<string>();

            try
            {
                // Compare code supplied to the code in the database.
                var savedCode = await _context.MfaCodeTable.Where(c => c.UserId == user.Id && c.MFA_Code == code).FirstOrDefaultAsync();

                if(savedCode != null)
                {

                    // Check that it is within the accepted timeframe

                    // Returns an int less than 0 if current date is earlier than expiry date
                    // Returns 0 if they are the same
                    // Returns a an int greater than zero if current date is later than the expiry date.
                    int compareDates = DateTime.Compare(DateTime.UtcNow, savedCode.DateCodeExpires);

                    if (compareDates <= 0)
                    {
                        // Success. Code is confirmed and is current!

                        // Remove the used code from the database.
                        var usedCode = await _context.MfaCodeTable.Where(t => t.UserId == user.Id && t.MFA_Code == code).FirstAsync();

                        if (usedCode != null)
                        {
                            _context.MfaCodeTable.Remove(usedCode);
                            _context.SaveChanges();
                        }

                        return true;
                    }
                    else
                    {
                        // Fail. Code is NOT current! Code has expired!

                        // delete expired refresh token
                        _context.MfaCodeTable.Remove(savedCode);
                        _context.SaveChanges();

                        _logger.LogInformation("Expired MFA Code Supplied By User! - MyMFA.ConfirmCode - UserName: {0}", user.UserName);

                        return false;
                    }
                    
                }

                _logger.LogInformation("Unconfirmed MFA Code Supplied By User! - MyMFA.ConfirmCode - UserName: {0}", user.UserName);

                // Signal that the code is unconfirmed.
                return false;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in MyMFA.ConfirmCode - {0}", ex.Message);

                // Signal that the code is unconfirmed.
                return false;

            }
        }

        public async Task<bool> CodePruning(AppUser user)
        {
            var serviceResponse = new ServiceResponse<string>();

            try
            {

                // Cleanup, delete expired codes for this user.
                // Only ever have 3 valid codes at the one time.
                // Keep 2 codes active here ( skip(2) ) as a new code will be added next in user login flow.
                // Every login generates a new code and they take 20 mins to expire.
                // A bot could generate 1000 valid codes.
                var expiredCodes = await _context.MfaCodeTable.Where(t => t.UserId == user.Id).OrderByDescending(x => x.DateCodeExpires).Skip(2).ToListAsync();

                if (expiredCodes != null && expiredCodes.Count > 0)
                {
                    _context.MfaCodeTable.RemoveRange(expiredCodes);
                    _context.SaveChanges();
                }

                // Signal that code pruning was successful.
                return true;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in MyMFA.CodePruning - User: {0} Exception: {1}", user.UserName, ex.Message);

                // Signal that code pruning failed.
                return false;

            }
        }


        /*
         * 
         * This method of pruning will leave any codes generated in the last hour in the database.
         * And any codes generated in the last 20 mins as active.
         * A bot could request 1000 codes in the 20 minute window they are "active" and not "expired" and all of them would be valid!
         * 
        public async Task<bool> CodePruning(AppUser user)
        {
            var serviceResponse = new ServiceResponse<string>();

            try
            {

                // Cleanup, delete expired codes for this user.
                var expiredCodesList = await _context.MfaCodeTable.Where(t => t.UserId == user.Id && t.DateCodeExpires.AddHours(1) < DateTime.UtcNow).ToListAsync();

                if (expiredCodesList != null)
                {
                    _context.MfaCodeTable.RemoveRange(expiredCodesList);
                    _context.SaveChanges();
                }

                // Signal that code pruning was successful.
                return true;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in MyMFA.CodePruning - User: {0} Exception: {1}", user.UserName, ex.Message);

                // Signal that code pruning failed.
                return false;

            }
        }
        */
    }
}
