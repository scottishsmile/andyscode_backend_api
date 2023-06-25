using API.Data;
using API.Dtos.v2_0.User;
using API.Models;
using API.Models.v2_0;
using API.Services.v2_0;
using API.Services.v2_0.EmailService;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;

namespace API.Controllers.v2_0.SubModules
{
    public class ControllerSubModulesV2 : IControllerSubModulesV2
    {
        // SUB-MODULES


        private readonly AppDbContext _context;
        public readonly UserManager<AppUser> _userManager;
        private readonly ILogger<ControllerSubModulesV2> _logger;
        private readonly JwtBearerTokenSettings _jwtBearerTokenSettings;
        private readonly IOptions<EmailConfigV2> _emailConfig;                 // Get appsettings.json configs
        private readonly IEmailServiceV2 _email;
        private readonly IOptions<MyMFASettings> _MyMFASettings;


        public ControllerSubModulesV2(AppDbContext context, UserManager<AppUser> userManager, ILogger<ControllerSubModulesV2> logger,
            IOptions<JwtBearerTokenSettings> jwtTokenOptions, IOptions<EmailConfigV2> emailConfig, IEmailServiceV2 email, IOptions<MyMFASettings> MyMFASettings)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
            _jwtBearerTokenSettings = jwtTokenOptions.Value;
            _emailConfig = emailConfig;
            _email = email;
            _MyMFASettings = MyMFASettings;
        }


        public async Task<AppUser> GetUserByEmailOrUserName(string usernameOrEmail)
        {
            try
            {
                // User may have supplied UserName OR Email address to login
                // It could be an email address inside credentials.UserName

                // Find by Email
                var user = await _userManager.FindByEmailAsync(usernameOrEmail);

                if (user == null)
                {
                    // If Email search returns null, try UserName
                    user = await _userManager.FindByNameAsync(usernameOrEmail);
                }

                if (user != null)
                {
                    // Sucess! We got a user object either by email or by username.
                    return user;
                }


                // Fail - Nothing worked.
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.GetUserByEmailOrUserName - {1}", ex.Message);
                return null;
            }
        }


        public async Task<AppUser> GetUserByEmailOrUserNameAndVerifyPassword(UserLoginDto credentials)
        {
            try
            {
                // User may have supplied UserName OR Email address to login
                // It could be an email address inside credentials.UserName

                // Find by Email
                var user = await _userManager.FindByEmailAsync(credentials.UserName);

                if (user == null)
                {
                    // If Email search returns null, try UserName
                    user = await _userManager.FindByNameAsync(credentials.UserName);
                }

                if (user != null)
                {

                    // Either FindByEmail or FindByName worked!
                    // Check their password is correct.
                    var result = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, credentials.Password);

                    
                    if (result == PasswordVerificationResult.Failed)
                    {
                        // Increment "Access Failed Count"
                        // So we can track how many failed login attempts there have been.
                        await _userManager.AccessFailedAsync(user);

                        // If the Password verification failed, return null.
                        return null;
                    }

                    // If the Password verification succeded, return the user object.
                    return user;
                }

                // Fail - Nothing worked.
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.GetUserByEmailOrUserName - {1}", ex.Message);
                return null;
            }
        }


        // Access Token
        public (string token, DateTime DateTokenExpires) GenerateAccessToken(AppUser user, IList<string> userRoles)
        {

            var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.AccessTokenSecretKey);

            // Generate the Name and Email Claims
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName.ToString()),
                // Don't want to add email address to the JWT token.
                // A hacker could use javascript to steal the token from the user's browser local storage. Token can be decrypted and email found.
                // The hacker then knows the website, the user's email AND username. They could send a very convincing phishing email.
                //new Claim(ClaimTypes.Email, user.Email),      

            };

            var dateTokenExpires = DateTime.UtcNow.AddMinutes(_jwtBearerTokenSettings.AccessTokenExpiryTimeInMinutes);

            // User Roles Claims will be added as a List
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var authSigningKey = new SymmetricSecurityKey(key);

            var tokenDetails = new JwtSecurityToken(
                issuer: _jwtBearerTokenSettings.Issuer,
                audience: _jwtBearerTokenSettings.Audience,
                expires: dateTokenExpires,                                                                                       // Access token lasts X MINUTES.
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha512)
                );


            // Generate Token
            var token = new JwtSecurityTokenHandler().WriteToken(tokenDetails);

            return (token.ToString(), dateTokenExpires);
        }


        // Refresh Token
        public async Task<RefreshTokenTable> GenerateRefreshToken(AppUser user, string? refreshToken = null)
        {
            var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.RefreshTokenSecretKey);

            // Refresh Token does not need claims.

            var authSigningKey = new SymmetricSecurityKey(key);

            var dateTokenExpires = DateTime.UtcNow.AddMinutes(_jwtBearerTokenSettings.RefreshTokenExpiryTimeInMinutes);

            var tokenDetails = new JwtSecurityToken(
                issuer: _jwtBearerTokenSettings.Issuer,
                audience: _jwtBearerTokenSettings.Audience,
                expires: dateTokenExpires,                                                                                       // Refresh Token lasts X MINUTES
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha512)
                );

            // Generate new refresh token
            var token = new JwtSecurityTokenHandler().WriteToken(tokenDetails);

            // Create new refresh token object. Used in our database table. We need to track which refresh tokens are assigned to which users.
            var newRefreshToken = new RefreshTokenTable
            {
                UserId = user.Id,
                RefreshToken = token,
                DateTokenIssued = DateTime.UtcNow,
                DateTokenExpires = dateTokenExpires
            };

            // Remove the current Refresh token from the database if it was passed to us.
            try
            {
                if (refreshToken != null)
                {

                    // Find the the old refresh token
                    var oldToken = await _context.RefreshTokenTable.Where(t => t.RefreshToken == refreshToken).FirstOrDefaultAsync();

                    if (oldToken != null)
                    {
                        // delete old refresh token
                        _context.RefreshTokenTable.Remove(oldToken);
                    }
                    else
                    {
                        _logger.LogError("Couldn't find old refresh token! ControllerSubModule.GenerateRefreshToken - USER: {0} - Token: {1}", user.Id, refreshToken);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception! Couldn't find old refresh token! ControllerSubModule.GenerateRefreshToken - USER: {0} - Token: {1}", user.Id, refreshToken);
            }

            // Add the new refresh token to the database so we can confirm it in the future.
            var addToken = await _context.RefreshTokenTable.AddAsync(newRefreshToken);

            // Save changes to database
            await _context.SaveChangesAsync();

            return newRefreshToken;
        }



        // Validate Refresh Token
        public bool ValidateRefreshToken(string refreshToken)
        {
            try
            {
                var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.RefreshTokenSecretKey);

                // Refresh Token does not need claims.

                var authSigningKey = new SymmetricSecurityKey(key);

                // The same validation parameters that are in Program.cs
                var validationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false,
                    ValidIssuer = _jwtBearerTokenSettings.Issuer,
                    ValidateAudience = false,
                    ValidAudience = _jwtBearerTokenSettings.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),               // Use RefreshTokenSecretKey. Program.cs uses AccessTokenSecretKey
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var tokenHandler = new JwtSecurityTokenHandler();

                // Check token is in JWT format and secret key matches
                // Exceptions will be thrown if the token is invalid!
                var validation = tokenHandler.ValidateToken(refreshToken, validationParameters, out SecurityToken validatedToken);

                return true;

            }
            catch (Exception ex)
            {
                _logger.LogError("Refresh Token is invalid! Exception in ControllerSubModule.ValidateRefreshToken - {0}", ex.Message);
                return false;
            }
        }


        public async Task<bool> RefreshTokenIsCurrent(string token)
        {
            try
            {
                // Get Token object
                var refreshToken = await _context.RefreshTokenTable.FirstOrDefaultAsync(x => x.RefreshToken == token);

                if (refreshToken != null)
                {
                    // Returns an int less than 0 if current date is earlier than refresh token date
                    // Returns 0 if they are the same
                    // Returns a an int greater than zero if current date is later than refresh token date.
                    int compareDates = DateTime.Compare(DateTime.UtcNow, refreshToken.DateTokenExpires);

                    if (compareDates <= 0)
                    {
                        // TESTING
                        _logger.LogInformation("RefreshTokenIsCurrent - True - Token: {0}", token);

                        // Success. Token is current! Token has not expired!
                        return true;
                    }
                    else
                    {
                        // TESTING
                        _logger.LogInformation("RefreshTokenIsCurrent - False. Removing Token. - Token: {0}", token);

                        // Fail. Token is NOT current! Token has expired!

                        // delete expired refresh token
                        _context.RefreshTokenTable.Remove(refreshToken);
                        _context.SaveChanges();

                        return false;
                    }
                }

                // TESTING
                _logger.LogInformation("RefreshTokenIsCurrent - False. Could not find token. - Token: {0}", token);

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.RefreshTokenExpiryDateCheck - {0}", ex.Message);
                return false;
            }
        }


        public async Task<bool> RefreshTokenIsAssignedToUser(string token, string userId)
        {
            try
            {
                // Get Token object
                var refreshToken = await _context.RefreshTokenTable.FirstOrDefaultAsync(x => x.RefreshToken == token);

                if (refreshToken != null)
                {
                    if (refreshToken.UserId == userId)
                    {
                        // Success
                        // Token assigned to correct user.
                        return true;
                    }
                    else
                    {
                        // Fail
                        // Token assigned to wrong user.
                        return false;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.RefreshTokenIsAssignedToUser - {0}", ex.Message);
                return false;
            }
        }



        public async Task<bool> RefreshTokenPruning(AppUser user)
        {
            try
            {
                // Find tokens from the user that have an expiry date of EARLIER than the current date (have expired)
                // LINQ uses .Date to convert the Table "DateTokenExpires" to a DateTime object so it can be compared with DateTime.UtcNow 
                // I was getting some client side refresh token issues when I made the pruning DateTokenExpires.Date < DateTime.UtcNow.
                // Exceptions looking for tokens that didn't exist?
                // So keep tokens for 1 week after their expiry, just incase, before pruning.
                // t.DateTokenExpires.Date.AddDays(7) < DateTime.UtcNow
                var expiredTokensList = await _context.RefreshTokenTable.Where(t => t.UserId == user.Id && t.DateTokenExpires.Date.AddDays(7) < DateTime.UtcNow).ToListAsync();

                if (expiredTokensList != null && expiredTokensList.Count() > 0)
                {
                    // TESTING
                    _logger.LogError("ControllerSubModule.RefreshTokenPruning - removing tokens for user: {0} tokens: {1}", user.UserName, expiredTokensList);

                    // Delete the exired tokens
                    _context.RefreshTokenTable.RemoveRange(expiredTokensList);
                    _context.SaveChanges();
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.RefreshTokenPruning - {0}", ex.Message);
                return false;
            }

        }


        public async Task<bool> SendConfirmEmail(AppUser user)
        {
            try
            {
                // Token
                // Generate confirm token, to be sent in the email so we know the user is verified.
                // We have to encode it into base64url to use it in the browser with JWT
                var token = WebUtility.UrlEncode(await _userManager.GenerateEmailConfirmationTokenAsync(user));

                // Link with token for validation and the user's username
                // VerifyEmail is the front end webpage. It will take the username and token from the url and send to User/ConfirmEmail API
                var confirmationlink = _emailConfig.Value.AdminWebsiteUrl + "EmailLink/VerifyEmail?UserName=" + user.UserName + "&Token=" + token;

                string subject = "Confirm your email";
                string message = $@"<p>One more step to register! Ignore this email if you did not request a user account with us.</p>
                            <p>Please click the link to verify your email address: <a href='{confirmationlink}'>Verify Email Address</a><p>";

                // Only allow 1 email verification per hour to stop SPAM.
                // We compare the DateTime of the LastConfirmEmailSent to the current time and see if it's greater than an hour.
                var compareTimes = (DateTime.UtcNow - user.LastConfirmEmailSent).Duration().TotalMinutes;

                if (compareTimes > Constants.Defaults.EMAIL_COMPARE_TIME)
                {
                    _email.SendEmail(user.Email, subject, message);
                    user.LastConfirmEmailSent = DateTime.UtcNow;                // Track time last verify email was sent
                    await _context.SaveChangesAsync();                          // SaveChangesAsync() is an Entity command to write changes to the database.
                    return true;
                }

                return false;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.SendConfirmEmail - {1}", ex.Message);
                return false;
            }
        }

        public async Task<bool> SendChangeEmailConfirmation(AppUser user, string newEmail)
        {
            try
            {
                // Token
                // Generate confirm token, to be sent in the email so we know the user is verified.
                // Notice that we are using .GenerateChangeEmailTokenAsync() and not .GenerateEmailConfirmationTokenAsync()
                // Each UserManager method has a matching token encoder! You must use the correct pair or the tokens will be invalid.

                // Weird formatting error? This will work when the user clicks on the link but NOT when pasted into the API.
                // I think GenerateChangeEmailTokenAsync() gives th etoken in an encoded format of some kind?
                // Remove the WebUtility.UrlEncode() and it'll work in the API and NOT in the browser link...
                var token = WebUtility.UrlEncode(await _userManager.GenerateChangeEmailTokenAsync(user, newEmail));


                // Link with token for validation and the user's Id
                // Best to use ID and not UserName as the username may be updated as well. It just gets confusing.
                // VerifyEmail is the front end webpage. It will take the username and token from the url and send to User/ConfirmEmail API
                var confirmationlink = _emailConfig.Value.AdminWebsiteUrl + "EmailLink/VerifyEmailChange?Id=" + user.Id + "&Token=" + token;

                string subject = "Confirm your email address change";
                string message = $@"<p>Please confirm that you want to change your account's email address. Ignore this email if you did not request changing your email address.</p>
                            <p>Please click the link to verify your email address: <a href='{confirmationlink}'>Verify Email Address</a><p>";

                // To avoid SPAM, put a hold timer on sending emails. 10 mins or something. That way
                // We compare the DateTime of the LastConfirmEmailSent to the current time and see if it's greater than our setting
                var compareTimes = (DateTime.UtcNow - user.LastConfirmEmailSent).Duration().TotalMinutes;

                if (compareTimes > Constants.Defaults.EMAIL_COMPARE_TIME)
                {
                    _email.SendEmail(user.UnconfirmedEmail, subject, message);  // Send email to the new "unconfirmed" address. User can still log in wit old email.
                    user.LastConfirmEmailSent = DateTime.UtcNow;                // Track time last verify email was sent
                    await _context.SaveChangesAsync();                          // SaveChangesAsync() is an Entity command to write changes to the database.
                    return true;
                }

                return false;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.ChangeEmailConfirmation - {1}", ex.Message);
                return false;
            }
        }


        public async Task<bool> AdminSendChangeEmailConfirmation(AppUser user, string newEmail)
        {
            try
            {
                // Token
                // Generate confirm token, to be sent in the email so we know the user is verified.
                // Notice that we are using .GenerateChangeEmailTokenAsync() and not .GenerateEmailConfirmationTokenAsync()
                // Each UserManager method has a matching token encoder! You must use the correct pair or the tokens will be invalid.

                // Weird formatting error? This will work when the user clicks on the link but NOT when pasted into the API.
                // I think GenerateChangeEmailTokenAsync() gives th etoken in an encoded format of some kind?
                // Remove the WebUtility.UrlEncode() and it'll work in the API and NOT in the browser link...
                var token = WebUtility.UrlEncode(await _userManager.GenerateChangeEmailTokenAsync(user, newEmail));

                // Link with token for validation and the user's Id
                // Best to use ID and not UserName as the username may be updated as well. It just gets confusing.
                // VerifyEmail is the front end webpage. It will take the username and token from the url and send to User/ConfirmEmail API
                var confirmationlink = _emailConfig.Value.AdminWebsiteUrl + "EmailLink/VerifyEmailChange?Id=" + user.Id + "&Token=" + token;

                string subject = "Confirm your email address change";
                string message = $@"<p>The admin user has changed your account's email address. Please confirm that this email address is yours by clicking the link below.</p>
                            <p>Please click the link to verify your email address: <a href='{confirmationlink}'>Verify Email Address</a><p>";

                // Admin User has no Compare times If Statement, we need them to be able to send out an email even if the user has just changed their email!

                _email.SendEmail(user.UnconfirmedEmail, subject, message);  // Send email to the new "unconfirmed" address. User can still log in wit old email.
                user.LastConfirmEmailSent = DateTime.UtcNow;                // Track time last verify email was sent
                await _context.SaveChangesAsync();                          // SaveChangesAsync() is an Entity command to write changes to the database.

                return true;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.AdminChangeEmailConfirmation - {1}", ex.Message);
                return false;
            }
        }


        public async Task<bool> SendPasswordResetEmail(AppUser user)
        {
            try
            {
                // Token
                // Generate password reset token, to be sent in the email so we know the user is verified.
                // We have to encode it into base64url to use it in the browser with JWT
                var token = WebUtility.UrlEncode(await _userManager.GeneratePasswordResetTokenAsync(user));

                // Link with token for validation and the user's username
                // ResetPassword is the front end webpage. It will call the User/ChangePassword API
                var resetLink = _emailConfig.Value.AdminWebsiteUrl + "EmailLink/ResetPass?UserName=" + user.UserName + "&Token=" + token;

                string subject = "Reset Your Password!";
                string message = $@"<p>Follow the below link to reset your password. Ignore this email if you did not request a password reset.</p>
                            <p>Please click the link to change your password: <a href='{resetLink}'>Change Password</a><p>";

                // To avoid SPAM, put a hold timer on sending emails. 10 mins or something. That way
                // We compare the DateTime of the LastConfirmEmailSent to the current time and see if it's greater than our setting
                var compareTimes = (DateTime.UtcNow - user.LastPasswordResetEmailSent).Duration().TotalMinutes;

                if (compareTimes > Constants.Defaults.EMAIL_COMPARE_TIME)
                {
                    _email.SendEmail(user.Email, subject, message);  // Send email to the new "unconfirmed" address. User can still log in wit old email.
                    user.LastPasswordResetEmailSent = DateTime.UtcNow;                // Track time last verify email was sent
                    await _context.SaveChangesAsync();                          // SaveChangesAsync() is an Entity command to write changes to the database.
                    return true;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.SendPasswordResetEmail - {1}", ex.Message);
                return false;
            }
        }

        public async Task<bool> AdminSendPasswordResetEmail(AppUser user)
        {
            try
            {
                // Token
                // Generate password reset token, to be sent in the email so we know the user is verified.
                // We have to encode it into base64url to use it in the browser with JWT
                var token = WebUtility.UrlEncode(await _userManager.GeneratePasswordResetTokenAsync(user));

                // Link with token for validation and the user's username
                // ResetPassword is the front end webpage. It will call the User/ChangePassword API
                var resetLink = _emailConfig.Value.AdminWebsiteUrl + "EmailLink/ResetPass?UserName=" + user.UserName + "&Token=" + token;

                string subject = "Reset Your Password!";
                string message = $@"<p>The admin user has changed your password. They should email you the new password directly.</p>";

                _email.SendEmail(user.Email, subject, message);  // Send email to the new "unconfirmed" address. User can still log in wit old email.
                user.LastPasswordResetEmailSent = DateTime.UtcNow;                // Track time last verify email was sent
                await _context.SaveChangesAsync();                          // SaveChangesAsync() is an Entity command to write changes to the database.

                return true;

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.AdminSendPasswordResetEmail - {1}", ex.Message);
                return false;
            }
        }


        public async Task<bool> ValidateEmailAddress(string email)
        {
            try
            {
                // Check for correct email address

                // Regex
                // Matches email addresses with subdomains, @ symbol, avoids double dots etc
                // Found online: https://www.rhyous.com/2010/06/15/csharp-email-regular-expression/
                if (Regex.IsMatch(email, @"^[\w!#$%&'*+\-/=?\^_`{|}~]+(\.[\w!#$%&'*+\-/=?\^_`{|}~]+)*@((([\-\w]+\.)+[a-zA-Z]{2,4})|(([0-9]{1,3}\.){3}[0-9]{1,3}))\z"))
                {
                    return true;
                }
                else
                {
                    _logger.LogError("Email is Invalid! WRONG! ControllerSubModule.ValidateEmailAddress - {1}", email);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.ValidateEmailAddress - {1}", ex.Message);
                return false;
            }
        }


        // Check if the Token is in Base64 format or not.
        // The token got from the Email Link WILL be in this format already as it's been through the browser url field
        // If you copy and paste the token from the email directly into the API it WILL NOT be in this format!
        // https://stackoverflow.com/questions/6309379/how-to-check-for-a-valid-base64-encoded-string
        public bool IsBase64String(string base64)
        {
            Span<byte> buffer = new Span<byte>(new byte[base64.Length]);
            return Convert.TryFromBase64String(base64, buffer, out int bytesParsed);
        }


        public async Task<bool> RecordLastLogin(AppUser user)
        {
            try
            {
                // Record the user's last login Date/time
                user.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();                          // SaveChangesAsync() is an Entity command to write changes to the database.

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.RecordLastLogin - {0}", ex.Message);
                return false;
            }
        }



        // MFA Token
        // Multi-Factor Authentication
        public async Task<MfaTokenTable> GenerateMfaToken(AppUser user, string? mfaToken = null)
        {

            var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.MfaTokenSecretKey);

            // Mfa Token does not need claims.

            var authSigningKey = new SymmetricSecurityKey(key);

            // Make the MFA token last as long as the code.
            var dateTokenExpires = DateTime.UtcNow.AddMinutes(_MyMFASettings.Value.MFACodeExpiryTimeInMinutes);

            var tokenDetails = new JwtSecurityToken(
                issuer: _jwtBearerTokenSettings.Issuer,
                audience: _jwtBearerTokenSettings.Audience,
                expires: dateTokenExpires,                                                                                       // Refresh Token lasts X MINUTES
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha512)
                );

            // Generate new refresh token
            var token = new JwtSecurityTokenHandler().WriteToken(tokenDetails);

            // Create new refresh token object. Used in our database table. We need to track which refresh tokens are assigned to which users.
            var newMfaToken = new MfaTokenTable
            {
                UserId = user.Id,
                MfaToken = token,
                DateTokenIssued = DateTime.UtcNow,
                DateTokenExpires = dateTokenExpires
            };

            // Remove the current Refresh token from the database if it was passed to us.
            try
            {
                if (mfaToken != null)
                {

                    // Find the the old refresh token
                    var oldToken = await _context.MfaTokenTable.Where(t => t.MfaToken == mfaToken).FirstOrDefaultAsync();

                    if (oldToken != null)
                    {
                        // delete old refresh token
                        _context.MfaTokenTable.Remove(oldToken);
                    }
                    else
                    {
                        _logger.LogError("Couldn't find old MFA token! ControllerSubModule.GenerateMfaToken - USER: {0} - Token: {1}", user.Id, mfaToken);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception! Couldn't find old MFA token! ControllerSubModule.GenerateMfaToken - USER: {0} - Token: {1}", user.Id, mfaToken);
            }

            // Add the new refresh token to the database so we can confirm it in the future.
            await _context.MfaTokenTable.AddAsync(newMfaToken);

            // Save changes to database
            await _context.SaveChangesAsync();

            return newMfaToken;
        }



        // Validate MFA Token
        public bool ValidateMfaToken(string token)
        {
            try
            {
                var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.MfaTokenSecretKey);

                // Refresh Token does not need claims.

                var authSigningKey = new SymmetricSecurityKey(key);

                // The same validation parameters that are in Program.cs
                var validationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false,
                    ValidIssuer = _jwtBearerTokenSettings.Issuer,
                    ValidateAudience = false,
                    ValidAudience = _jwtBearerTokenSettings.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),               // Use MfaTokenSecretKey. Program.cs uses AccessTokenSecretKey
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var tokenHandler = new JwtSecurityTokenHandler();

                // Check token is in JWT format and secret key matches
                // Exceptions will be thrown if the token is invalid!
                var validation = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                return true;

            }
            catch (Exception ex)
            {
                _logger.LogError("MFA Token is invalid! Exception in ControllerSubModule.ValidateMfaToken - {0}", ex.Message);
                return false;
            }
        }


        public async Task<bool> MfaTokenIsCurrent(string token)
        {
            try
            {
                // Get Token object
                var mfaToken = await _context.MfaTokenTable.FirstOrDefaultAsync(x => x.MfaToken == token);

                if (mfaToken != null)
                {
                    // Returns an int less than 0 if current date is earlier than refresh token date
                    // Returns 0 if they are the same
                    // Returns a an int greater than zero if current date is later than refresh token date.
                    int compareDates = DateTime.Compare(DateTime.UtcNow, mfaToken.DateTokenExpires);

                    if (compareDates <= 0)
                    {
                        // Success. Token is current! Token has not expired!
                        return true;
                    }
                    else
                    {
                        // Fail. Token is NOT current! Token has expired!

                        // delete expired refresh token
                        _context.MfaTokenTable.Remove(mfaToken);
                        _context.SaveChanges();

                        return false;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.MfaTokenExpiryDateCheck - {0}", ex.Message);
                return false;
            }
        }


        public async Task<bool> MfaTokenIsAssignedToUser(string token, string userId)
        {
            try
            {
                // Get Token object
                var mfaToken = await _context.MfaTokenTable.FirstOrDefaultAsync(x => x.MfaToken == token);

                if (mfaToken != null)
                {
                    if (mfaToken.UserId == userId)
                    {
                        // Success
                        // Token assigned to correct user.
                        return true;
                    }
                    else
                    {
                        // Fail
                        // Token assigned to wrong user.
                        return false;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.MfaTokenIsAssignedToUser - {0}", ex.Message);
                return false;
            }
        }


        public async Task<bool> MfaTokenPruning(AppUser user)
        {
            try
            {
                // Find tokens from the user that have an expiry date of EARLIER than the current date (have expired)
                var expiredTokensList = await _context.MfaTokenTable.Where(t => t.UserId == user.Id && t.DateTokenExpires.AddHours(1) < DateTime.UtcNow).ToListAsync();

                if (expiredTokensList != null && expiredTokensList.Count() > 0)
                {
                    // Delete the exired tokens
                    _context.MfaTokenTable.RemoveRange(expiredTokensList);
                    _context.SaveChanges();
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in ControllerSubModule.MfaTokenPruning - {0}", ex.Message);
                return false;
            }

        }

    }

}
