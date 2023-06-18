using API.Controllers.v1_0.SubModules;
using API.Data;
using API.Dtos.v1_0;
using API.Dtos.v1_0.User;
using API.Models;
using API.Models.v1_0;
using API.Services.v1_0.EmailService;
using API.Services.v1_0.Newsletter;
using API.Validation.v1_0;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog.Context;
using System.Diagnostics;
using System.Security.Claims;
using System.Net;

namespace API.Controllers.v1_0
{

    // All Identity Core methods are here - https://learn.microsoft.com/en-us/previous-versions/aspnet/dn613059(v=vs.108)

    [ApiController]
    [Route("/v{version:apiVersion}/[controller]")]
    [ApiVersion("1.0", Deprecated = true)]
    public class UserController : Controller
    {
        private readonly AppDbContext _context;
        public readonly UserManager<AppUser> _userManager;
        public readonly SignInManager<AppUser> _signInManager;
        private readonly ILogger<UserController> _logger;
        private readonly INewsletterV1 _newsletter;
        private readonly IHttpContextAccessor _httpContextAccessor;             // Access user ID inside the JWT token for the current HTTP session
        private IPasswordHasher<AppUser> _passwordHasher;                       // ASP.NET Identity Module
        private IPasswordValidator<AppUser> _passwordValidator;                 // ASP.NET Identity Module
        private IUserValidator<AppUser> _userValidator;                         // ASP.NET Identity Module
        private readonly IOptions<EmailConfigV1> _emailConfig;                 // Get appsettings.json configs
        private readonly IEmailServiceV1 _email;
        private IControllerSubModulesV1 _subModule;
        private readonly IValidateV1 _validate;


        public UserController(AppDbContext context, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ILogger<UserController> logger,
            INewsletterV1 newsletter, IHttpContextAccessor httpContextAccessor, IPasswordHasher<AppUser> passwordHasher, IPasswordValidator<AppUser> passwordValidator, 
            IUserValidator<AppUser> userValidator, IOptions<EmailConfigV1> emailConfig, IEmailServiceV1 email, IControllerSubModulesV1 subModule, IValidateV1 validate)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _newsletter = newsletter;
            _httpContextAccessor = httpContextAccessor;
            _passwordHasher = passwordHasher;
            _passwordValidator = passwordValidator;
            _userValidator = userValidator;
            _emailConfig = emailConfig;
            _email = email;
            _subModule = subModule;
            _validate = validate;
        }

        // For testing
        // Unsecured.
        // yoursite.com/User/Hello
        [AllowAnonymous]
        [HttpGet]
        [Route("Hello")]
        public async Task<ActionResult<ServiceResponse<bool>>> Hello(ApiVersion version)
        {
            Debug.WriteLine("v1.0 HELLO WORKS!!!!");

            using (LogContext.PushProperty("ApiVersion", version))
            {
                _logger.LogInformation("ApiVersion: {ApiVersion} - Hello Controller V1.0!", "v" + version);
            }
            ServiceResponse<bool> response = new ServiceResponse<bool>();
            response.Success = true;
            response.Message = "Hello! v1.0";
            return Ok(response);
        }

        // For testing
        // Use to test Authorization is working. Every role can access this. Bearer token from login should allow access.
        // yoursite.com/User/SecuredBasicHello
        [Authorize(Roles = "AppBasic, AppPremium, AppAdmin")]
        [HttpGet]
        [Route("SecuredBasicHello")]
        public async Task<ActionResult<ServiceResponse<bool>>> SecuredBasicHello(ApiVersion version)
        {
            Debug.WriteLine("v1.0 SECURED BASIC HELLO WORKS!!!!");

            using (_logger.BeginScope(new Dictionary<string, object>() { { "ApiVersion", version } }))
            {
                _logger.LogInformation($"ApiVersion: {version} - Secured Basic Hello Controller V1.0!");
            }

            ServiceResponse<bool> response = new ServiceResponse<bool>();
            response.Success = true;
            response.Message = "Secured Basic Hello Works! v1.0";
            return Ok(response);
        }

        // For testing
        // Use to test only premium and admin users can access this.
        // yoursite.com/User/SecuredBasicHello
        [Authorize(Roles = "AppPremium, AppAdmin")]
        [HttpGet]
        [Route("SecuredPremiumHello")]
        public async Task<ActionResult<ServiceResponse<bool>>> SecuredPremiumHello()
        {
            Debug.WriteLine("SECURED PREMIUM HELLO WORKS!!!!");
            ServiceResponse<bool> response = new ServiceResponse<bool>();
            response.Success = true;
            response.Message = "Secured Premium Hello Works!";
            return Ok(response);
        }


        // REGISTER
        // yoursite.com/User/Register
        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult<ServiceResponse<bool>>> Register(UserRegisterDto request, ApiVersion version)
        {
            try
            {
                ServiceResponse<bool> response = new ServiceResponse<bool>();

                // We will validate the Username, Email and Password in the UserRegisterDto.
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.emailValidation(request.Email) + _validate.alphabetValidation(request.Password)
                    + _validate.alphabetValidation(request.GivenName) + _validate.alphabetValidation(request.FamilyName) + _validate.alphabetValidation(request.AddressNumber)
                    + _validate.alphabetValidation(request.AddressLine1) + _validate.alphabetValidation(request.AddressLine2) + _validate.alphabetValidation(request.City)
                    + _validate.alphabetValidation(request.State) + _validate.alphabetValidation(request.Country) + _validate.alphabetValidation(request.PostCode) 
                    + _validate.alphabetValidation(request.Language) +_validate.alphabetValidation(request.Timezone);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Check if user already exists
                    var userExists = await _userManager.FindByNameAsync(request.UserName);

                    if (userExists != null)
                    {
                        response.Success = false;
                        response.Message = "Username has been taken. Try Another.";
                        _logger.LogInformation("ApiVersion: {ApiVersion} - Username has been taken. Try Another. Username Already Exists! UserController.Register - USER: {1} - EMAIL: {2}", version, request.UserName, request.Email);
                        return StatusCode(StatusCodes.Status500InternalServerError, response);
                    }

                    // Create New User
                    var user = new AppUser
                    {
                        Email = request.Email,
                        UserName = request.UserName,
                        GivenName = request.GivenName,
                        FamilyName = request.FamilyName,
                        AddressNumber = request.AddressNumber,
                        AddressLine1 = request.AddressLine1,
                        AddressLine2 = request.AddressLine2,
                        City = request.City,
                        State = request.State,
                        Country = request.Country,
                        PostCode = request.PostCode,
                        Language = request.Language,
                        Timezone = request.Timezone,
                        Newsletter = request.Newsletter,
                        RegistrationDate = DateTime.UtcNow
                    };

                    var createUser = await _userManager.CreateAsync(user, request.Password);

                    if (createUser.Succeeded)
                    {
                        // Identity Core Success
                        // Give them the default AppBasic role.
                        await _userManager.AddToRoleAsync(user, "AppBasic");

                        // Send confirmation email
                        await _subModule.SendConfirmEmail(user);


                        // Newsletter Subscription
                        if (request.Newsletter == true)
                        {
                            var newsletterResponse = await _newsletter.Subscribe(user);
                        }

                        response.Success = true;
                        response.Message = "Success!";
                        return Ok(response);
                    }
                    if (createUser.Errors.FirstOrDefault().Code == "DuplicateEmail")
                    {
                        // User's Email Already Exists!
                        response.Success = false;
                        response.Message = "That email address is already taken.";
                        _logger.LogInformation("ApiVersion: {ApiVersion} - An Account With That Email Already Exists. Failed Registration Attempt. in UserController.Register - USER: {1} - EMAIL: {2} - Errors: {3}", version, request.UserName, request.Email, createUser.Errors);
                        return BadRequest(response);
                    }

                    response.Success = false;
                    response.Message = "Failed To Create User. Check Password Meets Standards.";
                    _logger.LogInformation("ApiVersion: {ApiVersion} - Failed To Create User in UserController.Register - USER: {1} - EMAIL: {2} - Errors: {3}", version, request.UserName, request.Email, createUser.Errors);
                    return BadRequest(response);


                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.Register - USER: {1} - EMAIL: {2}", version, request.UserName, request.Email);

                return BadRequest(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.Register - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // Unique Username Check
        // Allow Frontend to Check if Username is Unique
        [AllowAnonymous]
        [HttpPost]
        [Route("UniqueUsernameCheck")]
        public async Task<ActionResult<ServiceResponse<bool>>> UniqueUsernameCheck(UniqueUsernameCheckDto request, ApiVersion version)
        {
            ServiceResponse<bool> response = new ServiceResponse<bool>();
            try
            {
                int passValidation = _validate.alphabetValidation(request.UserName);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0 && request.UserName != "nothing_supplied")
                {
                    // Check if user already exists
                    var userExists = await _userManager.FindByNameAsync(request.UserName);

                    if (userExists == null)
                    {
                        response.Success = true;
                        response.Message = "Username is unique";
                        return Ok(response);
                    }

                    response.Success = false;
                    response.Message = "Username has been taken. Try Another.";
                    _logger.LogInformation("ApiVersion: {ApiVersion} - Username has been taken. Try Another. Username Already Exists! UserController.UniqueUsernameCheck - USERNAME CHECKED: {0}", version, request.UserName);
                    return BadRequest(response);

                }
                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.UniqueUsernameCheck - USERNAME CHECKED: {0}", version, request.UserName);

                return BadRequest(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.UniqueUsernameCheck - {0}", version, ex.Message);

                return NotFound();
            }
        }




        // Confirm Email
        // www.yoursite.com/User/ConfirmEmail?UserName=BenTen10&Token=111222333444
        [AllowAnonymous]
        [HttpPost]
        [Route("ConfirmEmail")]
        public async Task<ActionResult<ServiceResponse<bool>>> ConfirmEmail(ConfirmEmailDto request, ApiVersion version)
        {
            ServiceResponse<bool> response = new ServiceResponse<bool>();
            try
            {
                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.jwtTokenValidation(request.Token);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    var user = await _userManager.FindByNameAsync(request.UserName);

                    if (user != null)
                    {
                        // Confirm Email Address
                        // Identity provides the token in the wrong format.
                        // We need to encode it to base64url when sending the email and then decode it when we grab it from the url.
                        // If this is not done you will get an "Invalid Token" error.


                        // Check if the Token is in Base64 format or not.
                        // The token got from the Email Link WILL be in this format already as it's been through the browser url field
                        // If you copy and paste the token from the email directly into the API it WILL NOT be in this format!
                        bool tokenCheck = _subModule.IsBase64String(request.Token);
                        string decodedToken;

                        if (tokenCheck == false)
                        {
                            // Decode the Token from base64url
                            decodedToken = WebUtility.UrlDecode(request.Token);
                        } else
                        {
                            // No need to decode token
                            decodedToken = request.Token;
                        }

                        // Attempt to confirm the email address using the username and decoded token.
                        var confirmEmail = await _userManager.ConfirmEmailAsync(user, decodedToken);

                        if (confirmEmail.Succeeded)
                        {
                            // Success!
                            response.Success = true;
                            response.Message = "Success! Email Confirmed!";
                            return Ok(response);
                        }
                        else
                        {
                            // Failed
                            response.Success = false;
                            response.Message = "Fail! Cannot confirm email address. Token may be invalid.";
                            return BadRequest(response);
                        }
                    }

                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "Email Couldn't Be Confirmed.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - Email Couldn't Be Confirmed in UserController.ConfirmEmail - USER: {1}", version, request.UserName);

                    return BadRequest(response);


                }
                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.ConfirmEmail - USER: {1}", version, request.UserName);

                return BadRequest(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.ConfirmEmail - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // Change Email - Confirm Email
        // www.yoursite.com/User/VerifyEmailChange?UserName=BenTen10&Token=111222333444
        // When updating user emails, we want to keep their original email address "working" and record the new email as "UnconfirmedEmail".
        // A confirmation token will be sent to the new "UnconfirmedEmail" address and end up at this endpoint.
        // If the token matches we will update the user's email address with the new email saved in UnconfirmedEmail.
        [AllowAnonymous]
        [HttpPost]
        [Route("VerifyEmailChange")]
        public async Task<ActionResult<ServiceResponse<bool>>> VerifyEmailChange(VerifyEmailChangeDto request, ApiVersion version)
        {
            ServiceResponse<bool> response = new ServiceResponse<bool>();
            try
            {
                int passValidation = _validate.alphabetValidation(request.Id) + _validate.jwtTokenValidation(request.Token);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    var user = await _userManager.FindByIdAsync(request.Id);

                    if (user != null)
                    {
                        // Confirm Email Address
                        // Identity provides the token in the wrong format.
                        // We need to encode it to base64url when sending the email and then decode it when we grab it from the url.
                        // If this is not done you will get an "Invalid Token" error.

                        // DO NOT! Decode the Token from base64url with ChangeEmailAsync
                        // The module it's paired with to create the token auto adds base64url and .ChangeEmailAsync() auto decodes base64url.
                        // Unlike the ConfirmEmail module which does need it encoded.
                        // string decodedToken = WebUtility.UrlDecode(request.Token);

                        // Change the user's email address.
                        // Use ChangeEmailAsync(user, new email, confirm_token) Idneity has a special module for this.

                        // Check if the Token is in Base64 format or not.
                        // The token got from the Email Link WILL be in this format already as it's been through the browser url field
                        // If you copy and paste the token from the email directly into the API it WILL NOT be in this format!

                        // Decode the Token from base64url
                        bool tokenCheck = _subModule.IsBase64String(request.Token);
                        string decodedToken;

                        if (tokenCheck == false)
                        {
                            // Decode the Token from base64url
                            decodedToken = WebUtility.UrlDecode(request.Token);
                        }
                        else
                        {
                            // No need to decode token
                            decodedToken = request.Token;
                        }


                        var changeEmail = await _userManager.ChangeEmailAsync(user, user.UnconfirmedEmail, decodedToken);


                        if (changeEmail.Succeeded)
                        {
                            // Success!
                            response.Success = true;
                            response.Message = "Success! Email Changed!";
                            return Ok(response);
                        }
                        else
                        {
                            // Failed
                            response.Success = false;
                            response.Message = "Fail! Cannot confirm email address. Token may be invalid.";
                            return BadRequest(response);
                        }
                    }

                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "Email Couldn't Be Confirmed.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - Email Couldn't Be Confirmed in UserController.VerifyEmailChange - USER ID: {1}", version, request.Id);

                    return BadRequest(response);


                }
                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.VerifyEmailChange - USER ID: {1}", version, request.Id );

                return BadRequest(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.VerifyEmailChange - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // UPGRADE TO PREMIUM
        // yoursite.com/User/PremiumUpgrade
        // At the moment anyone can just access this url and upgrade themselves to premium. If they know the url.
        // It would usually be hidden BEHIND the payment gateway. So users only see it AFTER a paypal/Gpay payment.
        // Maybe there's some additional checks that can be done (tokens?) with the payment gateway to confirm client has paid?
        // Or an AWS lambda function inside your secure network does this rather than it being an API call. That way spammers can't access it.
        // Or have this API ONLY able to be called by the payment gateway API or a service it initializes. So only the payment gateway service is authorized to upgrade users.
        [Authorize(Roles = "AppBasic")]
        [HttpPost]
        [Route("PremiumUpgrade")]
        public async Task<ActionResult<ServiceResponse<bool>>> PremiumUpgrade(PremiumUpgradeDto request, ApiVersion version)
        {
            try
            {
                ServiceResponse<bool> response = new ServiceResponse<bool>();

                // We will validate the Username and Email in the PremiumUpgradeDto.
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.alphabetValidation(request.Id);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Get the user
                    var user = await _userManager.FindByIdAsync(request.Id);

                    if (user != null)
                    {
                        // Check the username matches the ID supplied in the DTO request.
                        // Spammers may just send in a bunch of usernames!
                        bool truthCheck = false;
                        if (request.Id == user.Id)
                        {
                            truthCheck = true;
                        }

                        if (truthCheck == true)
                        {

                            // Premium User Upgrade
                            await _userManager.AddToRoleAsync(user, "AppPremium");

                            // You could also have a Notification Email Sent.
                            // Inform the user that they are now have Premium access.
                            // The user has to log out and in again to get the token with the AppPremium role.
                            string subject = "Premium Access Enabled!";
                            string message = $@"<p>Welcome to our Premium membership! You can now access the VIP areas of the site. Please log out and log in again to get it working.<p>";

                            _email.SendEmail(user.Email, subject, message);

                            response.Success = true;
                            response.Message = "Success!";
                            return Ok(response);
                        }
                    }

                    response.Success = false;
                    response.Message = "User Doesn't Exist!";
                    _logger.LogInformation("ApiVersion: {ApiVersion} - User Doesn't Exist! Maybe user's email address didn't match suplied email in DTO request. UserController.PremiumUpgrade - USER: {1} - Id: {2}", version, request.UserName, request.Id);
                    return StatusCode(StatusCodes.Status500InternalServerError, response);

                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.PremiumUpgrade - USER: {1} - Id: {2}", version, request.UserName, request.Id);

                return BadRequest(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.PremiumUpgrade - {1}", version, ex.Message);

                return NotFound();
            }
        }


        // LOGIN
        // yoursite.com/User/Login
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<ServiceResponse<LoginResponseDto>>> Login(UserLoginDto request, ApiVersion version)
        {
            try
            {

                var response = new ServiceResponse<LoginResponseDto>();

                // We will validate the Username and Password in the UserLoginDto.
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.alphabetValidation(request.Password);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Check user exists and password is correct
                    // If password is wrong increment "Access Failed Count" in the Identity database.
                    AppUser user = await _subModule.GetUserByEmailOrUserNameAndVerifyPassword(request);

                    if (user != null)
                    {
                        // Check account is not locked
                        // User will ONLY be told their account is locked once they enter their correct password.
                        // This way hackers won't know how many attempts they have.
                        if (await _userManager.IsLockedOutAsync(user) == false)
                        {
                            // Check if email address has been confirmed
                            if (await _userManager.IsEmailConfirmedAsync(user) == true)
                            {
                                // Get List of the user's roles
                                var userRoles = await _userManager.GetRolesAsync(user);

                                // Create a JWT access token for the user to login
                                // It should expire quickly.
                                // We will add the user's role list to the token. That way it's hashed.
                                var accessToken = _subModule.GenerateAccessToken(user, userRoles);

                                // Refresh token lasts longer than the access token.
                                // Don't want hackers to get the access token. If we change the password but the old token hasn't expired yet the hacker still has access.
                                // Also allows users to stay logged into the app longer.
                                var newRefreshToken = await _subModule.GenerateRefreshToken(user);


                                // Refresh Token Pruning
                                // Check for expired refresh tokens and delete them.
                                // Could maybe be better handled in a recurring servcie run by Hangfire? Rather than in the login endpoint? Easier on the database.
                                var refreshTokenPruning = await _subModule.RefreshTokenPruning(user);


                                LoginResponseDto loginReply = new LoginResponseDto();
                                loginReply.AccessToken = accessToken.token;
                                loginReply.AccessTokenExpiry = accessToken.DateTokenExpires;
                                loginReply.RefreshToken = newRefreshToken.RefreshToken;
                                loginReply.RefreshTokenExpiry = newRefreshToken.DateTokenExpires;
                                loginReply.Id = user.Id;
                                loginReply.Email = user.Email;
                                loginReply.Username = user.UserName;
                                loginReply.Roles = userRoles;                // User roles are already in the JWT token. Maybe remove this?


                                // Reset "Access Failed Count" to 0
                                // The user has logged in, they get another 5 (or whatever) login attempts next time.
                                await _userManager.ResetAccessFailedCountAsync(user);

                                // Record date/time of user's login
                                bool lastLogin = await _subModule.RecordLastLogin(user);

                                response.Data = loginReply;
                                response.Success = true;
                                response.Message = "Success!";

                                return Ok(response);
                            }
                            else
                            {
                                // Email Not Confirmed
                                // Send a message to tell user of the error
                                response.Success = false;
                                response.Message = "Email Not Confirmed! Confirmation Email Resent. Please check your email, it may be in the junk folder.";

                                _logger.LogInformation("ApiVersion: {ApiVersion} - Email Not Confirmed! - UserController.Login - USER: {0}", version, request.UserName);

                                // Re-Send confirmation email
                                // This function won't allow resending of multiple spam confirm emails. 1 per hour.
                                await _subModule.SendConfirmEmail(user);

                                return Unauthorized(response);
                            }
                        }

                        // User's account is locked

                        // Send a message to tell user of the error
                        response.Success = false;
                        response.Message = "Account Locked! Wait 15 min or reset password.";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - User's Account is Locked! - UserController.Login - USER: {0}", version, request.UserName);

                        return Unauthorized(response);

                    }

                    // Send a message to tell user of the error
                    // Unfortunately Identity Core doesn't let you flag to the user the email isn't confirmed.
                    // It will just return a null for the user until email address is confirmed.
                    // They want to lower the attack surface as an attacker might span the API looking for email addresses that exists and this would return a hit.
                    // A feature request for confirming the password matches and then checking if the email is confirmed has been raised but not implimented yet.
                    // https://github.com/dotnet/AspNetCore/issues/5410
                    response.Success = false;
                    response.Message = "User Doesn't Exist or Password is wrong.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - User Doesn't Exist or Wrong Password in UserController.Login - USER: {0}", version, request.UserName);

                    return BadRequest(response);

                }



                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.Login - USER: {1}", version, request.UserName);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.Login - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // REFRESH TOKENS
        // The refresh token will eventually expire and will need replaced.
        // Access tokens allow Access to the app and are only available for a short amount of time, minutes.
        // A refresh token lasts much longer, days.
        // You can use the refresh token to get a new access token when the client is started! Without having to login again!
        // Important! A NEW refresh token is generated EVERYTIME an access token is requested. This is industry standard. The previous refresh token is then deleted from our table.
        [AllowAnonymous]
        [HttpPost]
        [Route("Refresh")]
        public async Task<ActionResult<ServiceResponse<RefreshResponseDto>>> Refresh(RefreshTokenDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<RefreshResponseDto>();

                int passValidation = _validate.jwtTokenValidation(request.RefreshToken) + _validate.alphabetValidation(request.UserName);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Validate the submitted refresh token
                    // Token is in JWT format and matches the refresh secret key
                    var isValid = _subModule.ValidateRefreshToken(request.RefreshToken);

                    if (isValid)
                    {
                        // Lookup user
                        var user = await _userManager.FindByNameAsync(request.UserName);

                        if (user != null)
                        {
                            // Multiple devices may have multiple active refresh tokens.
                            // We keep a list of the active tokens.
                            // Check the RefreshTokens list contains the passed in refresh token.
                            string? tokenExists = await _context.RefreshTokenTable.Where(t => t.RefreshToken == request.RefreshToken).Select(t => t.RefreshToken).FirstOrDefaultAsync();

                            if (tokenExists != null)
                            {

                                // Check Token Expiry Date
                                // Check the token from our database,not the one submitted, as the dates could be forged.
                                var tokenIsCurrent = await _subModule.RefreshTokenIsCurrent(tokenExists);

                                if (tokenIsCurrent == true)
                                {
                                    // Check that refresh token is assigned to the supplied user.
                                    var tokenIsAssignedToUser = await _subModule.RefreshTokenIsAssignedToUser(tokenExists, user.Id);

                                    if (tokenIsAssignedToUser == true)
                                    {

                                        // Success                                  

                                        RefreshTokenTable newRefreshToken = new RefreshTokenTable();
                                        (string? token, DateTime DateTokenExpires) newAccessToken = (null, DateTime.UtcNow);
                                        IList<string> userRoles = new List<string>();

                                        try
                                        {
                                            // Create new tokens
                                            newRefreshToken = await _subModule.GenerateRefreshToken(user, request.RefreshToken);
                                            userRoles = await _userManager.GetRolesAsync(user);                                         // Get List of the user's roles
                                            newAccessToken = _subModule.GenerateAccessToken(user, userRoles);
                                        }
                                        catch (Exception ex)
                                        {
                                            _logger.LogError("ApiVersion: {ApiVersion} - Exception generating tokens! UserController.Refresh - USER: {0} - ERROR: {1}", version, request.UserName, ex.Message);
                                        }

                                        if (newRefreshToken != null && newAccessToken.token != null)
                                        {                                         

                                            RefreshResponseDto refreshReply = new RefreshResponseDto();
                                            refreshReply.RefreshToken = newRefreshToken.RefreshToken;
                                            refreshReply.RefreshTokenExpiry = newRefreshToken.DateTokenExpires;
                                            refreshReply.AccessToken = newAccessToken.token;
                                            refreshReply.AccessTokenExpiry = newAccessToken.DateTokenExpires;

                                            response.Data = refreshReply;
                                            response.Success = true;
                                            response.Message = "Success!";

                                            return Ok(response);
                                        }
                                        else
                                        {
                                            _logger.LogError("ApiVersion: {ApiVersion} - Access Or Refresh Tokens were not generated. UserController.Refresh - USER: {0}", version, request.UserName);
                                            return BadRequest(response);
                                        }
                                    }
                                    else
                                    {
                                        // Fail
                                        // Refresh token is not assigned to the supplied user!
                                        _logger.LogError("ApiVersion: {ApiVersion} - Refresh Token doesn't match the user in our database. UserController.Refresh - USER: {0}", version, request.UserName);

                                        response.Success = false;
                                        response.Message = "Refresh Token Doesn't Match";

                                        return BadRequest(response);
                                    }
                                }
                                else
                                {
                                    // Fail
                                    // Refresh token was valid but has expired
                                    // No need to log this, there may be lots of them and they won't indicate an error or hacking attempt.

                                    response.Success = false;
                                    response.Message = "Refresh Token Has Expired";

                                    return BadRequest(response);
                                }

                            }
                            else
                            {
                                // Refresh Tokens Don't Match
                                _logger.LogError("ApiVersion: {ApiVersion} - Refresh Tokens Don't Match. UserController.Refresh - USER: {0}", version, request.UserName);
                                _logger.LogError("ApiVersion: {ApiVersion} - UserController.Refresh - tokenIsCurrent returned false. Refresh Token Supplied: {0}", version, request.RefreshToken);

                                
                                response.Success = false;
                                response.Message = "Refresh Tokens Doesn't Exist.";

                                return BadRequest(response);
                            }

                        }
                        else
                        {
                            // User Not Found
                            _logger.LogError("ApiVersion: {ApiVersion} - User Not Found. UserController.Refresh - USER: {0}", version, request.UserName);

                            response.Success = false;
                            response.Message = "User Not Found.";

                            return BadRequest(response);
                        }
                    }
                    else
                    {
                        // Invalid Token.
                        _logger.LogError("ApiVersion: {ApiVersion} - Invalid Refresh Token. UserController.Refresh - USER: {0}", version, request.UserName);

                        response.Success = false;
                        response.Message = "Invalid Refresh Token.";

                        return BadRequest(response);
                    }
                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.Refresh - USER: {0}", version, request.UserName);

                return NotFound(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.Refresh - USER: {0} - ERROR: {1}", version, request.UserName, ex.Message);
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.Refresh - Refresh Token Supplied: {0}", version, request.RefreshToken);

                return NotFound();
            }
        }



        // VERIFY REFRESH TOKEN
        // No need to create a new access and refresh token, we just need to verify it here
        // Return 200 OK if it is still valid.
        // Return 400 Bad Request if not valid.
        // The frontend can use this to find out if the refresh token has expired. If it is still valid then keep the user logged in.
        // If we were to use the "refresh" endpoint we would generate new tokens everytime we checked if it was still valid.
        [AllowAnonymous]
        [HttpPost]
        [Route("VerifyRefreshToken")]
        public async Task<ActionResult<ServiceResponse<RefreshResponseDto>>> VerifyRefreshToken(RefreshTokenDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<RefreshResponseDto>();

                int passValidation = _validate.jwtTokenValidation(request.RefreshToken) + _validate.alphabetValidation(request.UserName);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Validate the submitted refresh token
                    // Token is in JWT format and matches the refresh secret key
                    var isValid = _subModule.ValidateRefreshToken(request.RefreshToken);

                    if (isValid)
                    {
                        // Lookup user
                        var user = await _userManager.FindByNameAsync(request.UserName);

                        if (user != null)
                        {
                            // Multiple devices may have multiple active refresh tokens.
                            // We keep a list of the active tokens.
                            // Check the RefreshTokens list contains the passed in refresh token.
                            string? tokenExists = await _context.RefreshTokenTable.Where(t => t.RefreshToken == request.RefreshToken).Select(t => t.RefreshToken).FirstOrDefaultAsync();

                            if (tokenExists != null)
                            {

                                // Check Token Expiry Date
                                // Check the token from our database,not the one submitted, as the dates could be forged.
                                var tokenIsCurrent = await _subModule.RefreshTokenIsCurrent(tokenExists);

                                if (tokenIsCurrent == true)
                                {
                                    // Check that refresh token is assigned to the supplied user.
                                    var tokenIsAssignedToUser = await _subModule.RefreshTokenIsAssignedToUser(tokenExists, user.Id);

                                    if (tokenIsAssignedToUser == true)
                                    {

                                        // Success! Refresh token is still valid.
                                        // 200 OK response.

                                        return Ok(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
                                    }
                                    else
                                    {
                                        // Fail
                                        // Refresh token is not assigned to the supplied user!
                                        _logger.LogError("ApiVersion: {ApiVersion} - Refresh Token doesn't match the user in our database. UserController.VerifyRefreshToken - USER: {0}", version, request.UserName);

                                        response.Success = false;
                                        response.Message = "Refresh Token Doesn't Match";

                                        return BadRequest(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
                                    }
                                }
                                else
                                {
                                    // Fail
                                    // Refresh token was valid but has expired
                                    // No need to log this, there may be lots of them and they won't indicate an error or hacking attempt.

                                    response.Success = false;
                                    response.Message = "Refresh Token Has Expired";

                                    return BadRequest(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
                                }

                            }
                            else
                            {
                                // Refresh Tokens Don't Match
                                _logger.LogError("ApiVersion: {ApiVersion} - Refresh Tokens Don't Match. UserController.VerifyRefreshToken - USER: {0}", version, request.UserName);

                                response.Success = false;
                                response.Message = "Refresh Tokens Doesn't Exist.";

                                return BadRequest(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
                            }

                        }
                        else
                        {
                            // User Not Found
                            _logger.LogError("ApiVersion: {ApiVersion} - User Not Found. UserController.VerifyRefreshToken - USER: {0}", version, request.UserName);

                            response.Success = false;
                            response.Message = "User Not Found.";

                            return BadRequest(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
                        }
                    }
                    else
                    {
                        // Invalid Token.
                        _logger.LogError("ApiVersion: {ApiVersion} - Invalid Refresh Token. UserController.VerifyRefreshToken - USER: {0}", version, request.UserName);

                        response.Success = false;
                        response.Message = "Invalid Refresh Token.";

                        return BadRequest(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
                    }
                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.VerifyRefreshToken - USER: {0}", version, request.UserName);

                return BadRequest(response);     // Verify Refresh Token response either 200 OK or 400 Bad Request!
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.VerifyRefreshToken - USER: {0} - ERROR: {1}", version, request.UserName, ex.Message);

                return BadRequest();        // Verify Refresh Token response either 200 OK or 400 Bad Request!
            }
        }




        // LOGOUT
        // Delete Active Refresh Token
        // The access token will still ve valid, but it has a short lifespan.
        // Not implimented - add the access token to a blacklist or find a way to also delete it.
        [Authorize]
        [HttpPost]
        [Route("Logout")]
        public async Task<ActionResult<ServiceResponse<bool>>> Logout(LogoutDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<bool>();

                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.jwtTokenValidation(request.RefreshToken);

                if (passValidation == 0)
                {
                    // Validate the submitted refresh token
                    // Token is in JWT format and matches the refresh secret key
                    var isValid = _subModule.ValidateRefreshToken(request.RefreshToken);

                    if (isValid)
                    {
                        // Lookup user
                        var user = await _userManager.FindByNameAsync(request.UserName);

                        // We could also get user from the JWT Access token. They are [Authorized]
                        // Rather than from the DTO.
                        // var username = HttpContext.User.FindFirstValue("UserName");
                        // var user = await _userManager.FindByNameAsync(username);
                        // or
                        // Our GetUserName() submodule does same thing! Bottom of the page.

                        if (user != null)
                        {
                            // Get Token object
                            var tokenExists = await _context.RefreshTokenTable.FirstOrDefaultAsync(x => x.RefreshToken == request.RefreshToken);

                            if (tokenExists != null)
                            {

                                // Check that refresh token is assigned to the supplied user.
                                // Without this check, annyone with a refresh token could logout any other user if they supplied a different username in the request.
                                var tokenIsAssignedToUser = await _subModule.RefreshTokenIsAssignedToUser(tokenExists.RefreshToken, user.Id);

                                if (tokenIsAssignedToUser == true)
                                {
                                    // Delete Refresh Token From Database
                                    var remoteToken = _context.RefreshTokenTable.Remove(tokenExists);
                                    _context.SaveChanges();

                                    response.Success = true;
                                    response.Message = "You are logged out!";

                                    return Ok(response);
                                } else
                                {
                                    // Refresh Tokens Don't Match
                                    _logger.LogError("ApiVersion: {ApiVersion} - Refresh Tokens Don't Match. UserController.Logout - USER: {0}", version, request.UserName);

                                    response.Success = false;
                                    response.Message = "Refresh Tokens Doesn't Exist.";

                                    return BadRequest(response);
                                }
                            }
                            else
                            {
                                response.Success = false;
                                response.Message = "Token Not Found.";

                                return NotFound(response);
                            }

                        }
                        else
                        {
                            // User Not Found
                            _logger.LogError("ApiVersion: {ApiVersion} - User Not Found. UserController.Logout - USER: {0}", version, request.UserName);

                            response.Success = false;
                            response.Message = "User Not Found.";

                            return BadRequest(response);
                        }
                    }
                    else
                    {
                        // Invalid Token.
                        _logger.LogError("ApiVersion: {ApiVersion} - Invalid Refresh Token. UserController.Logout - USER: {0}", version, request.UserName);

                        response.Success = false;
                        response.Message = "Invalid Refresh Token.";

                        return BadRequest(response);
                    }
                }

                response.Success = false;
                response.Message = "Validation Failed";

                return BadRequest();
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.Logout - USER: {0} - ERROR: {1}", version, request.UserName, ex.Message);

                return NotFound();
            }

        }


        // RESEND CONFIRM EMAIL
        // yoursite.com/User/ResendConfirmEmail
        [AllowAnonymous]
        [HttpGet]
        [Route("ResendConfirmEmail/{email}")]
        public async Task<ActionResult<ServiceResponse<bool>>> ResendConfirmEmail(string email, ApiVersion version)
        {
            try
            {

                // Validate the email address
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.emailValidation(email);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Check user exists.
                    // The user object WILL exist even if the email wasn't confirmed yet.
                    AppUser user = await _userManager.FindByEmailAsync(email);

                    if (user != null)
                    {
                        // Send confirmation email
                        // This function won't allow resending of multiple spam confirm emails. 1 per hour.
                        await _subModule.SendConfirmEmail(user);

                        return Ok(true);
                    }

                        _logger.LogInformation("ApiVersion: {ApiVersion} - Unknown email address. User's email address doesn't exist in our database - UserController.ResendConfirmEmail - EMAIL: {1}", version, email);

                        return BadRequest(false);
                   

                }

                // Validation Failed
                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.ResendConfirmEmail - EMAIL: {1}", version, email);

                return NotFound(false);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.ResendConfirmEmail - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // FORGOT PASSWORD
        // User forgot password and is not logged in.
        // yoursite.com/User/ForgotPass
        [AllowAnonymous]
        [HttpPost]
        [Route("ForgotPass")]
        public async Task<ActionResult<ServiceResponse<bool>>> ForgotPass(ForgotPasswordDto request, ApiVersion version)
        {
            var response = new ServiceResponse<bool>();

            try
            {
                int passValidation = _validate.emailValidation(request.Email);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    var user = await _userManager.FindByEmailAsync(request.Email);

                    if (user != null)
                    {

                        // Reset Password By Email
                        _subModule.SendPasswordResetEmail(user);

                        // Success.
                        response.Success = true;
                        response.Message = "Password Reset Email Sent.";
                        return Ok(response);
                    }
                    else
                    {
                        // Send a message to tell user of the error
                        response.Success = false;
                        response.Message = "User Not Found.";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - User Not Found in UserController.ForgotPass - EMAIL: {1}", version, request.Email);

                        return NotFound(response);
                    }

                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.ForgotPass - EMAIL: {1}", version, request.Email);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.ForgotPass - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // CHANGE PASSWORD
        // User has been sent a password reset email. This API processes it.
        // User is not logged in.
        // yoursite.com/User/ChangePassword
        [AllowAnonymous]
        [HttpPut]
        [Route("ChangePassword")]
        public async Task<ActionResult<ServiceResponse<bool>>> ChangePassword(ChangePasswordDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<bool>();

                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.alphabetValidation(request.Password) + _validate.jwtTokenValidation(request.Token);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    var user = await _userManager.FindByNameAsync(request.UserName);

                    if (user != null)
                    {
                        // Change the password

                        // Identity provides the token in the wrong format.
                        // We need to encode it to base64url when sending the email and then decode it when we grab it from the url.
                        // If this is not done you will get an "Invalid Token" error.

                        // Decode the Token from base64url
                        bool tokenCheck = _subModule.IsBase64String(request.Token);
                        string decodedToken;

                        if (tokenCheck == false)
                        {
                            // Decode the Token from base64url
                            decodedToken = WebUtility.UrlDecode(request.Token);
                        }
                        else
                        {
                            // No need to decode token
                            decodedToken = request.Token;
                        }

                        var resetPassResult = await _userManager.ResetPasswordAsync(user, decodedToken, request.Password);

                        if (resetPassResult.Succeeded)
                        {
                            // Success.
                            response.Success = true;
                            response.Message = "Password Changed!";
                            return Ok(response);
                        }
                        else
                        {
                            // Send a message to tell user of the error
                            // Most common issues are an invalid token or the new password not meeting complexity requirements.
                            // Be sure to check the new password for strength in the front end form first. It's set in our program.cs
                            response.Success = false;
                            response.Message = "Password Change Failed. Check token and password complexity requirements.";

                            _logger.LogInformation("ApiVersion: {ApiVersion} - Password Change Failed in UserController.ChangePassword - USER: {1} - Error: {2}", version, request.UserName + resetPassResult);

                            return BadRequest(response);
                        }

                    }

                    // User not found
                    response.Success = false;
                    response.Message = "Fail! User doesn't exist.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - User Doesn't Exist in UserController.ChangePassword - USER: {1} ", version, request.UserName);

                    return NotFound(response);
                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.ChangePassword - USER: {1}", version, request.UserName);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.ChangePassword - {1}", version, ex.Message);

                return NotFound();
            }
        }


        // PASSWORD RESET
        // User is logged in and wants to change their password.
        // yoursite.com/User/ResetPass
        [Authorize(Roles = "AppBasic, AppPremium, AppAdmin")]
        [HttpPost]
        [Route("ResetPass")]
        public async Task<ActionResult<ServiceResponse<bool>>> ResetPass(PasswordResetDto request, ApiVersion version)
        {
            var response = new ServiceResponse<bool>();

            try
            {
                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.alphabetValidation(request.NewPassword);

                // Get the User's ID from the http session, check it's the same as the ID they want to update. Users can ONLY update themselves.
                // Check if the user's ID matches the updateSelf.Id ? [true] Get the user's info using Id : [false] return null
                AppUser user =
                    GetUserName().Equals(request.UserName) ?
                    await _userManager.FindByNameAsync(request.UserName) :
                    null;

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // PASSWORD
                    var validPassword = await _passwordValidator.ValidateAsync(_userManager, user, request.NewPassword);
                    if (!validPassword.Succeeded)
                    {
                        // Fail Password validation.
                        response.Success = false;
                        response.Message = "Password wasn't valid.";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - Password wasn't valid. in UserController.ResetPass - USER: {1} Error: {2}", version, request.UserName, validPassword);

                        return BadRequest(response);
                    }
                    else
                    {
                        // Success! Create new password hash.
                        user.PasswordHash = _passwordHasher.HashPassword(user, request.NewPassword);

                        // Update the user in the database, save the new password.
                        var updatePassword = await _userManager.UpdateAsync(user);

                        // Email user to tell them their password was changed.
                        string subject = "Password Change Notification";
                        string ResetPassUrl = Constants.HrefLinks.frontEndUrl_ResetPassword;
                        string contactUrl = Constants.HrefLinks.frontEndUrl_Contact;
                        string message = $@"<p>Your Password was changed. If you didn't change it, please contact us immediately.</p><p>You can reset it here: <a href='{ResetPassUrl}'>Reset Password</a></p><p>Contact us through the memers area form: <a href='{contactUrl}'>Contact</a></p>";
                        _email.SendEmail(user.Email, subject, message);

                        // Success.
                        response.Success = true;
                        response.Message = "Success. Password Changed.";
                        return Ok(response);
                    }

                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.ResetPass - USER: {1}", version, request.UserName);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("Exception in UserController.ResetPass - {1}", ex.Message);

                return NotFound();
            }
        }



        // GET USER
        // Refresh tokens allow the client to stay logged in over many days.
        // The refresh token contains UserName and Roles, but that's all.
        // The client won't have access to the user object returned from Login() after using refresh tokens several days later.
        // So we need a READ endpoint to GET the user info.
        [Authorize(Roles = "AppBasic, AppPremium, AppAdmin")]
        [HttpGet]
        [Route("GetUser/{username}")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> GetUser(string username, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<GetUserDto>();

                int passValidation = _validate.alphabetValidation(username);

                if (passValidation == 0)
                {

                    // Get User Object
                    AppUser user = await _subModule.GetUserByEmailOrUserName(username);

                    // Get the User's ID from the http session (JWT Token)
                    // Can't use username as it may change.
                    // Check the ID in the token is the same as the user they want to update. Users can ONLY update themselves.
                    string userIdLowercase = GetUserId().ToLower();                         // Will probably already be lowercase anyway but doesn't hurt.
                    bool userCheck = userIdLowercase.Equals(user.Id.ToLower());

                    if (user != null && userCheck == true)
                    {

                        // Manual Mapping between the AppUsers and the DTO we are sending out.
                        // Mapping could be done using AutoMapper OR Entity Select statement with mapping classes.
                        // Maual mapping is just quicker and easier for a small application.

                        GetUserDto userObject = new GetUserDto();

                        // Identity saves the roles in a seperate database table from the user.
                        // Unfortunately we now have to look up their roles list individually.
                        IList<string> userRoles = await _userManager.GetRolesAsync(user);
                        userObject.Roles = userRoles;

                        userObject.Id = user.Id;
                        userObject.Email = user.Email;
                        userObject.EmailVerified = null;                    // User doesn't need to see this.
                        userObject.UserName = user.UserName;
                        userObject.GivenName = user.GivenName;
                        userObject.FamilyName = user.FamilyName;
                        userObject.AddressNumber = user.AddressNumber;
                        userObject.AddressLine1 = user.AddressLine1;
                        userObject.AddressLine2 = user.AddressLine2;
                        userObject.City = user.City;
                        userObject.State = user.State;
                        userObject.Country = user.Country;
                        userObject.PostCode = user.PostCode;
                        userObject.Language = user.Language;
                        userObject.Timezone = user.Timezone;
                        userObject.AccountLocked = null;                    // User doesn't need to see this.


                        // Add the GetUserDto to the service response.
                        response.Data = userObject;

                        // Success
                        response.Success = true;
                        response.Message = "Success!";
                        return response;

                    }
                    else
                    {
                        // Send a message to tell user of the error
                        response.Success = false;
                        response.Message = "User Does Not Exist";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - User Does Not Exist. UserController.GetUser - USER: {0}", version, username);

                        return NotFound(response);
                    }
                }
                else
                {
                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "Validation Failed.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.GetUser - USER: {0}", version, username);

                    return NotFound(response);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.GetUser - {0}", version, ex.Message);

                return NotFound();
            }
        }



        // GET USER BY ID
        // User may update their username/email, so need to get them by Id.
        [Authorize(Roles = "AppBasic, AppPremium, AppAdmin")]
        [HttpGet]
        [Route("GetUserById/{id}")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> GetUserById(string id, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<GetUserDto>();

                int passValidation = _validate.alphabetValidation(id);

                if (passValidation == 0)
                {

                    // Get User Object
                    AppUser user = await _userManager.FindByIdAsync(id);

                    // Get the User's ID from the http session (JWT Token)
                    // Can't use username as it may change.
                    // Check the ID in the token is the same as the username they want to update. Users can ONLY update themselves.
                    string userIdLowercase = GetUserId().ToLower();                         // Will probably already be lowercase anyway but doesn't hurt.
                    bool userCheck = userIdLowercase.Equals(user.Id.ToLower());

                    if (user != null && userCheck == true)
                    {

                        // Manual Mapping between the AppUsers and the DTO we are sending out.
                        // Mapping could be done using AutoMapper OR Entity Select statement with mapping classes.
                        // Maual mapping is just quicker and easier for a small application.

                        GetUserDto userObject = new GetUserDto();

                        // Identity saves the roles in a seperate database table from the user.
                        // Unfortunately we now have to look up their roles list individually.
                        IList<string> userRoles = await _userManager.GetRolesAsync(user);
                        userObject.Roles = userRoles;

                        userObject.Id = user.Id;
                        userObject.Email = user.Email;
                        userObject.EmailVerified = null;                    // User doesn't need to see this.
                        userObject.UserName = user.UserName;
                        userObject.GivenName = user.GivenName;
                        userObject.FamilyName = user.FamilyName;
                        userObject.AddressNumber = user.AddressNumber;
                        userObject.AddressLine1 = user.AddressLine1;
                        userObject.AddressLine2 = user.AddressLine2;
                        userObject.City = user.City;
                        userObject.State = user.State;
                        userObject.Country = user.Country;
                        userObject.PostCode = user.PostCode;
                        userObject.Language = user.Language;
                        userObject.Timezone = user.Timezone;
                        userObject.AccountLocked = null;                    // User doesn't need to see this.


                        // Add the GetUserDto to the service response.
                        response.Data = userObject;

                        // Success
                        response.Success = true;
                        response.Message = "Success!";
                        return response;

                    }
                    else
                    {
                        // Send a message to tell user of the error
                        response.Success = false;
                        response.Message = "User Does Not Exist";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - User Does Not Exist. UserController.GetUserById - ID: {0}", version, id);

                        return NotFound(response);
                    }
                }
                else
                {
                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "Validation Failed.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.GetUserById - ID: {0}", version, id);

                    return NotFound(response);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.GetUserById - {0}", version, ex.Message);

                return NotFound();
            }
        }



        // UPDATE USER PROFILE
        // PUT Request
        // yoursite.com/User/UpdateSelf
        [Authorize(Roles = "AppBasic, AppPremium, AppAdmin")]
        [HttpPut]
        [Route("UpdateSelf")]
        public async Task<ActionResult<ServiceResponse<bool>>> UpdateSelf(UpdateUserDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<bool>();

                // We will validate the Username and Password in the UserLoginDto.
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.alphabetValidation(request.Email) + _validate.alphabetValidation(request.Id) + _validate.alphabetValidation(request.NewUserName) +
                    _validate.alphabetValidation(request.Password) + _validate.alphabetValidation(request.GivenName) + _validate.alphabetValidation(request.FamilyName)
                    + _validate.alphabetValidation(request.Language) + _validate.alphabetValidation(request.AddressNumber) + _validate.alphabetValidation(request.AddressLine1) 
                    + _validate.alphabetValidation(request.AddressLine2) + _validate.alphabetValidation(request.City) + _validate.alphabetValidation(request.State) 
                    + _validate.alphabetValidation(request.Country) + _validate.alphabetValidation(request.PostCode) + _validate.alphabetValidation(request.Timezone);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {

                    // Get the user object
                    // They may have changed their username AND email address
                    // So we use their ID to find them as that will remain unchanged.
                    AppUser user = await _userManager.FindByIdAsync(request.Id);


                    // Get the User's username from the http session (JWT Token)
                    // Check the username in the token is the same as the username they want to update. Users can ONLY update themselves.
                    string usernameLowercase = GetUserName().ToLower();                         // Will probably already be lowercase anyway but doesn't hurt.
                    bool userCheck = usernameLowercase.Equals(user.UserName.ToLower());

                    if (user != null && userCheck == true)
                    {
                        // Update User Details

                        // USERNAME CHANGE
                        if (!String.IsNullOrEmpty(request.NewUserName) && request.NewUserName != "unchanged")
                        {

                            // Check for unique user name. No other user has that user name.
                            // If the username hasn't changed then it will find the user object and skip the username change.
                            var uniqueUserName = await _userManager.FindByNameAsync(request.NewUserName);

                            if (uniqueUserName == null)
                            {
                                // Success! Map the username change.
                                user.UserName = request.NewUserName;
                            }
                        }

                        // PASSWORD CHANGE
                        if (!String.IsNullOrEmpty(request.Password) && request.Password != "unchanged")
                        {
                            // Only proceed if a new password has been supplied, the request.Password field will be null otherwise.

                            // Make sure password meets complexity requirements
                            var validPassword = await _passwordValidator.ValidateAsync(_userManager, user, request.Password);

                            if (!validPassword.Succeeded)
                            {
                                // Fail Password validation.
                                response.Success = false;
                                response.Message = "Password wasn't valid.";

                                _logger.LogInformation("ApiVersion: {ApiVersion} - Password wasn't valid. in UserController.UpdateSelf - USER ID: {1} Error: {2}", version, request.Id, validPassword);

                                return BadRequest(response);
                            }
                            else
                            {

                                // Email user to tell them their password was changed.
                                string adminEmail = _emailConfig.Value.AdminEmailAddress;
                                string subject = "Password Change Notification";
                                string message = $@"<p>Your Password was changed. If you didn't change it, please contact us immediately." + adminEmail + "</p>";
                                _email.SendEmail(user.Email, subject, message);
                            }
                        }

                        // EMAIL ADDRESS
                        if (!String.IsNullOrEmpty(request.Email) && request.Email != "unchanged")
                        {
                            // Check for unique email. No other user has that email address.
                            // If the email address hasn't changed then it will find the user object and skip the email change.
                            var uniqueEmail = await _userManager.FindByEmailAsync(request.Email);

                            if (uniqueEmail == null)
                            {
                                // Save the new email address as the user.UnconfirmedEmail
                                // We will only update the user object's user.Email when we have confirmed this new one.
                                // That way the user can log in with their old email address should they enter a WRONG email address. They won't be locked out.
                                user.UnconfirmedEmail = request.Email;

                                // Validate Email address
                                // Unfortunately, we can't use _userValidator.ValidateAsync() as it only accepts a whole user object and not an individual email address.
                                bool validEmail = await _subModule.ValidateEmailAddress(request.Email);

                                if (validEmail == true)
                                {
                                    // Update the user in the database, save UnconfirmedEmail.
                                    var updateEmail = await _userManager.UpdateAsync(user);

                                    if (updateEmail.Succeeded)
                                    {

                                        // Send confirmation email
                                        await _subModule.SendChangeEmailConfirmation(user, user.UnconfirmedEmail);

                                    }
                                    else
                                    {
                                        // Server Update Email Fail
                                        // Fail Email Validation.
                                        response.Success = false;
                                        response.Message = "Oops! We are having server problems...";

                                        _logger.LogInformation("ApiVersion: {ApiVersion} - Email Update failed. _userManager.UpdateAsync() failed. in UserController.UpdateSelf - USER ID: {1} Error: {2}", version, request.Id, validEmail);

                                        return BadRequest(response);
                                    }
                                }
                                else
                                {
                                    // Fail Email Validation.
                                    response.Success = false;
                                    response.Message = "Email wasn't valid.";

                                    _logger.LogInformation("ApiVersion: {ApiVersion} - Email wasn't valid. in UserController.UpdateSelf - USER ID: {1} Error: {2}", version, request.Id, validEmail);

                                    return BadRequest(response);
                                }

                            }
                        }

                        // Map the rest.

                        // You could do something fancy here like use an automapper
                        // Or create an array of the AppUser fields and then map them all to the corresponding requestDto fields
                        // I've just done them manually to save processing time.
                        // It menas if you update the AppUser object with a new field you have to manually update this part as well.

                        if (!String.IsNullOrEmpty(request.GivenName) && request.GivenName != "unchanged")
                        {
                            user.GivenName = request.GivenName;
                        }

                        if (!String.IsNullOrEmpty(request.FamilyName) && request.FamilyName != "unchanged")
                        {
                            user.FamilyName = request.FamilyName;
                        }

                        if (!String.IsNullOrEmpty(request.AddressNumber) && request.AddressNumber != "unchanged")
                        {
                            user.AddressNumber = request.AddressNumber;
                        }

                        if (!String.IsNullOrEmpty(request.AddressLine1) && request.AddressLine1 != "unchanged")
                        {
                            user.AddressLine1 = request.AddressLine1;
                        }

                        if (!String.IsNullOrEmpty(request.AddressLine2) && request.AddressLine2 != "unchanged")
                        {
                            user.AddressLine2 = request.AddressLine2;
                        }

                        if (!String.IsNullOrEmpty(request.City) && request.City != "unchanged")
                        {
                            user.City= request.City;
                        }

                        if (!String.IsNullOrEmpty(request.State) && request.State != "unchanged")
                        {
                            user.State = request.State;
                        }

                        if (!String.IsNullOrEmpty(request.Country) && request.Country != "unchanged")
                        {
                            user.Country = request.Country;
                        }

                        if (!String.IsNullOrEmpty(request.PostCode) && request.PostCode != "unchanged")
                        {
                            user.PostCode = request.PostCode;
                        }

                        if (!String.IsNullOrEmpty(request.Language) && request.Language != "unchanged")
                        {
                            user.Language = request.Language;
                        }

                        if (!String.IsNullOrEmpty(request.Timezone) && request.Timezone != "unchanged")
                        {
                            user.Timezone = request.Timezone;
                        }

                        // Update the user
                        var updateUser = await _userManager.UpdateAsync(user);

                        if (updateUser.Succeeded)
                        {
                            // Success.
                            response.Success = true;
                            response.Message = "Success!";
                            return Ok(response);
                        }
                        else
                        {
                            // Fail.
                            response.Success = false;
                            response.Message = "User Update Failed.";

                            _logger.LogInformation("ApiVersion: {ApiVersion} - User Update Failed in UserController.UpdateSelf - USER ID: {1} Error: {2}", version, request.Id, updateUser);

                            return BadRequest(response);
                        }
                    }
            

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "User Doesn't Exist.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - User Doesn't Exist in UserController.UpdateSelf - USER: {1}", version, request.Id);

                return BadRequest(response);

            }



                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.UpdateSelf - USER ID: {1}", version, request.Id);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.UpdateSelf - {1}", version, ex.Message);

                return NotFound();
            }
        }





        // Contact Us
        // Allows users to contact us via contact form on website.
        // yoursite.com/User/Contact
        [Authorize(Roles = "AppBasic, AppPremium, AppAdmin")]
        [HttpPost]
        [Route("Contact")]
        public async Task<ActionResult<ServiceResponse<bool>>> Contact(ContactDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<bool>();

                int passValidation = _validate.alphabetValidation(request.UserName);
                // Can't validate Subject or Message as they will be long. Message is 3000 chars. The chances of it randomly containing our badwords is high.

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {

                    // Get the user object
                    AppUser user = await _userManager.FindByNameAsync(request.UserName);

                    if (user != null)
                    {
                        // Send the message to the admin email address.
                        string siteTitle = _emailConfig.Value.SiteTitle;
                        string siteName = _emailConfig.Value.SiteName;
                        string subject = $@"{siteTitle} - User Contact Form - {request.Subject}";
                        string message = $@"{siteName} - User: {user.UserName} - Email: {user.Email} - Message: {request.Message}";

                        _email.SendEmailToAdmin(user.Email, subject, message);

                        response.Success = true;
                        response.Message = "Success!";
                        return Ok(response);

                    }


                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "User Doesn't Exist.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - User Doesn't Exist in UserController.Contact - USER: {0}", version, request.UserName);

                    return BadRequest(response);

                }



                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in UserController.Contact - USER ID: {0}", version, request.UserName);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in UserController.Contact - {0}", version, ex.Message);

                return NotFound();
            }
        }





        // SUB-MODULES



        // GET THE USER ID FROM THE CURRENT HTTP SESSION
        // User has logged in, so we can use HttpContextAccessor to grab to user's ID from the JWT token.
        // ClaimTypes.NameIdentifier gives the current user id, and ClaimTypes.Name gives the username.
        private string GetUserName() => _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);

        private string GetUserId() => _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);


        //private string GetUserRole() => _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Role);
        private IEnumerable<string> GetUserRoles() => _httpContextAccessor.HttpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value);

    }
}
