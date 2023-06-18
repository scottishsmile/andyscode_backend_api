using API.Controllers.v1_0.SubModules;
using API.Data;
using API.Dtos.v1_0;
using API.Dtos.v1_0.User;
using API.Models;
using API.Models.v1_0;
using API.Services.v1_0.Newsletter;
using API.Validation.v1_0;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace API.Controllers.v1_0
{
    [ApiController]
    [Route("/v{version:apiVersion}/Secret/[controller]")]
    [ApiVersion("1.0")]
    public class AdminController : Controller
    {

        private readonly AppDbContext _context;
        public readonly UserManager<AppUser> _userManager;
        public readonly SignInManager<AppUser> _signInManager;
        private readonly ILogger<AdminController> _logger;
        private readonly INewsletterV1 _newsletter;
        private readonly IHttpContextAccessor _httpContextAccessor;             // Access user ID inside the JWT token for the current HTTP session
        private IPasswordHasher<AppUser> _passwordHasher;                       // ASP.NET Identity Module
        private IPasswordValidator<AppUser> _passwordValidator;                 // ASP.NET Identity Module
        private IUserValidator<AppUser> _userValidator;                         // ASP.NET Identity Module
        private IControllerSubModulesV1 _subModule;
        private readonly IValidateV1 _validate;


        public AdminController(AppDbContext context, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ILogger<AdminController> logger,
            INewsletterV1 newsletter, IHttpContextAccessor httpContextAccessor, IPasswordHasher<AppUser> passwordHasher, IPasswordValidator<AppUser> passwordValidator,
            IUserValidator<AppUser> userValidator, IControllerSubModulesV1 subModule, IValidateV1 validate)
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
            _subModule = subModule;
            _validate = validate;
        }


        // ADMIN UPDATE USER PROFILE
        // PUT request
        // yoursite.com/Secret/Admin/AdminUpdateUser
        [Authorize(Roles = "AppAdmin")]
        [HttpPut]
        [Route("AdminUpdateUser")]
        public async Task<ActionResult<ServiceResponse<int>>> AdminUpdateUser(AdminUpdateUserDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<int>();

                // We will validate the Username and Password in the UserLoginDto.
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.alphabetValidation(request.Email) + _validate.alphabetValidation(request.Id) + _validate.alphabetValidation(request.NewUserName) +
                    _validate.alphabetValidation(request.Password) + _validate.alphabetValidation(request.GivenName) + _validate.alphabetValidation(request.FamilyName)
                    + _validate.alphabetValidation(request.AddressNumber) + _validate.alphabetValidation(request.AddressLine1) + _validate.alphabetValidation(request.AddressLine2)
                    + _validate.alphabetValidation(request.City) + _validate.alphabetValidation(request.State) + _validate.alphabetValidation(request.Country) + _validate.alphabetValidation(request.PostCode)
                    + _validate.alphabetValidation(request.Language) + _validate.alphabetValidation(request.Timezone);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Get the user object
                    // They may have changed their username AND email address
                    // So we use their Id, which should not have changed
                    AppUser user =
                     GetUserRoles().Contains("AppAdmin") ?
                    await _userManager.FindByIdAsync(request.Id) :
                    null;

                    if (user != null)
                    {
                        // Update User Details

                        // USERNAME
                        // Check for unique user name. No other user has that user name.
                        if (!String.IsNullOrEmpty(request.NewUserName) && request.NewUserName != "unchanged")
                        {
                            var uniqueUserName = await _userManager.FindByNameAsync(request.NewUserName);
                            if (uniqueUserName == null)
                            {
                                // Success! Map the username change.
                                user.UserName = request.NewUserName;
                            }
                        }

                        // PASSWORD
                        if (!String.IsNullOrEmpty(request.Password) && request.Password != "unchanged")
                        {
                            var validPassword = await _passwordValidator.ValidateAsync(_userManager, user, request.Password);
                            if (!validPassword.Succeeded)
                            {
                                // Fail Password validation.
                                response.Success = false;
                                response.Message = "Password wasn't valid.";

                                _logger.LogInformation("ApiVersion: {ApiVersion} - Password wasn't valid. in AdminController.AdminUpdateUser - USER ID : {1} Error: {2}", version, request.Id, validPassword);

                                return BadRequest(response);
                            }
                            else
                            {
                                // Success! Create new password hash.
                                user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

                                // Send notification email to tell user admin has changed their password.
                                // Admin will have to email them the password directly.
                                await _subModule.AdminSendPasswordResetEmail(user);

                            }
                        }

                        // EMAIL ADDRESS
                        if (!String.IsNullOrEmpty(request.Email) && request.Email != "unchanged")
                        {
                            // Check for unique email. No other user has that email address.
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

                                // Update the user in the database, save UnconfirmedEmail.
                                var updateEmail = await _userManager.UpdateAsync(user);

                                if (validEmail == true && updateEmail.Succeeded)
                                {

                                    // Send confirmation email
                                    await _subModule.AdminSendChangeEmailConfirmation(user, user.UnconfirmedEmail);

                                }
                                else
                                {
                                    // Fail Email Validation.
                                    response.Success = false;
                                    response.Message = "Email wasn't valid.";

                                    _logger.LogInformation("ApiVersion: {ApiVersion} - Email wasn't valid. in AdminController.AdminUpdateUser - USER ID: {1} Error: {2}", version, request.Id, validEmail);

                                    return BadRequest(response);
                                }

                            }
                        }


                        // ROLE
                        // Admin may want to upgrade them to premium or downgrade them to Basic.
                        if (!String.IsNullOrEmpty(request.Role) && request.Role != "unchanged")
                        {
                            // Identity saves the roles in a seperate database table from the user.
                            // Unfortunately we now have to look up their roles list individually.
                            IList<string> userRoles = await _userManager.GetRolesAsync(user);

                            if (request.Role == "AppPremium")
                            {
                                // Add the user to Premium
                                await _userManager.AddToRoleAsync(user, "AppPremium");
                            }

                            if (request.Role == "AppBasic")
                            {
                                // Check if the user has the AppPremium Role, if so delete it
                                // We can just check if the role is contained in userRoles IList we looked up or use .IsInRoleAsync()
                                // Using .IsInRoleAsync() is another database lookup but userRole.Contains() is just checking the List we already have.

                                // var premiumUser = _userManager.IsInRoleAsync(user, "AppPremium");

                                if (userRoles.Contains("AppPremium"))
                                {
                                    // Remove the Premium role if the user had it
                                    // If we ask it to remove a role that doesn't exist you will get an ArgumentNullException.
                                    try
                                    {
                                        await _userManager.RemoveFromRoleAsync(user, "AppPremium");
                                    }
                                    catch (ArgumentNullException ex)
                                    {
                                        _logger.LogError("ApiVersion: {ApiVersion} - ArgumentNullException. User never had AppPremium role - AdminController.AdminUpdateUser - {1}", version, ex.Message);
                                    }
                                }
                            }
                        }

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
                            user.City = request.City;
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
                            response.Message = "Success";
                            return Ok(response);
                        }
                        else
                        {
                            // Fail.
                            response.Success = false;
                            response.Message = "User Update Failed.";

                            _logger.LogInformation("ApiVersion: {ApiVersion} - User Update Failed in AdminController.AdminUpdateUser - USER ID: {1} Error: {2}", version, request.Id, updateUser);

                            return BadRequest(response);
                        }
                    }

                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "User Doesn't Exist.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - User Doesn't Exist in AdminController.AdminUpdateUser - USER ID: {1}", version, request.Id);

                    return BadRequest(response);

                }


                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.AdminUpdateUser - USER ID: {1}", version, request.Id);

                return NotFound(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.AdminUpdateUser - {1}", version, ex.Message);

                return NotFound();
            }
        }





        // REGISTER ADMIN USER
        // yoursite.com/Secret/Admin/RegisterAdmin
        // Maybe comment this out when you don't need it? No point having the endpoint active if it's not being used. A hacker could create admin users if breached.
        [Authorize(Roles = "AppAdmin")]                     // Only other admins can create admins
        [HttpPost]
        [Route("RegisterAdmin")]
        public async Task<ActionResult<ServiceResponse<int>>> RegisterAdmin(UserRegisterDto request, ApiVersion version)
        {
            try
            {
                ServiceResponse<int> response = new ServiceResponse<int>();

                // We will validate the Username, Email and Password in the UserRegisterDto.
                // Each of the validations returns 0 if it passed or 1 if it failed.
                int passValidation = _validate.alphabetValidation(request.UserName) + _validate.emailValidation(request.Email) + _validate.alphabetValidation(request.Password);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {
                    // Check if user already exists
                    var userExists = await _userManager.FindByNameAsync(request.UserName);

                    if (userExists != null)
                    {
                        response.Success = false;
                        response.Message = "User Already Exists!";
                        _logger.LogInformation("ApiVersion: {ApiVersion} - User Already Exists! AdminController.RegisterAdmin - USER: {1} - EMAIL: {2}", version, request.UserName, request.Email);
                        return StatusCode(StatusCodes.Status500InternalServerError, response);
                    }

                    // Create New User Object
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
                        RegistrationDate = DateTime.Now
                    };

                    // Pass the user object and the Password to Identity UserManager.
                    var createUser = await _userManager.CreateAsync(user, request.Password);

                    if (createUser.Succeeded)
                    {
                        // Identity Core Success
                        await _signInManager.SignInAsync(user, isPersistent: false);

                        // Make the user an Admin
                        await _userManager.AddToRoleAsync(user, "AppBasic");
                        await _userManager.AddToRoleAsync(user, "AppPremium");
                        await _userManager.AddToRoleAsync(user, "AppAdmin");

                        // Send confirmation email
                        await _subModule.SendConfirmEmail(user);

                        response.Success = true;
                        response.Message = "Success!";
                        return Ok(response);
                    }

                    response.Success = false;
                    response.Message = "Failed To Create Admin User. Check password complexity.";
                    _logger.LogInformation("ApiVersion: {ApiVersion} - Failed To Create User in AdminController.RegisterAdmin - USER: {1} - EMAIL: {2} - Errors: {3}", version, request.UserName, request.Email, createUser.Errors);
                    return BadRequest(response);


                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.RegisterAdmin - USER: {1} - EMAIL: {2}", version, request.UserName, request.Email);

                return BadRequest(response);

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.RegisterAdmin - {1}", version, ex.Message);

                return NotFound();
            }

        }



        // GET PAGED USERS
        // yoursite.com/Secret/Admin/GetPagedUsers
        [Authorize(Roles = "AppAdmin")]
        [HttpGet]
        [Route("GetPagedUsers/{currentPage}")]
        public async Task<ActionResult<ServiceResponse<GetPagedUserDto>>> GetPagedUsers(int currentPage, ApiVersion version)
        {
            try
            {

                var response = new ServiceResponse<GetPagedUserDto>();
                var Data = new GetPagedUserDto();
                string userName = String.Empty;                 // Provides username for logger via jwt token.

                int passValidation = _validate.numberValidation(currentPage.ToString());

                if (passValidation == 0)
                {

                    // There is no built in method to get a batch of users from Identity.
                    // There is  UserManager.Users.ToListAsync()  that will get all users. We don't want ALL of them, could be 1000s! We want them in batches of 50.
                    // Best way is to access the Identity database using Entity context and use .skip() and .take()

                    int maxRows = Constants.Admin.maxRows;


                    // Check if the user role is "admin" ? [true] Show all users in database : [false] return null
                    // Order the users A-Z by UserName
                    // Pages will hold x amount of records each. Say 50.
                    // If you are on Page1 records 1 - 50, Page2 51-100, Page3 101-150 etc.
                    // So page 2 would be SKIP 50 records. The current page is 2 so (2 - 1  = 1) then multiplay that by the amount of records we are grabbing maxRows. 1 * 50 = 50. So SKIP 50 records.

                    List<AppUser> dbUsers =
                    GetUserRoles().Contains("AppAdmin") ?
                    await _context.Users.OrderBy(u => u.UserName).Skip((currentPage - 1) * maxRows).Take(maxRows).ToListAsync() :
                    null;

                    if (dbUsers != null && dbUsers.Count > 0)
                    {

                        double pageCount = (double)((decimal)_context.Users.Count() / Convert.ToDecimal(maxRows));
                        int pages = (int)Math.Ceiling(pageCount);

                        Data.PageCount = pages;
                        Data.CurrentPageIndex = currentPage;


                        // Manual Mapping between the AppUsers and the DTO we are sending out.
                        // Mapping could be done using AutoMapper OR Entity Select statement with mapping classes.
                        // Maual mapping is just quicker and easier for a small application.

                        List<GetUserDto> pagedUserList = new List<GetUserDto>();

                        foreach (AppUser user in dbUsers)
                        {
                            GetUserDto userObject = new GetUserDto();

                            // Identity saves the roles in a seperate database table from the user.
                            // Unfortunately we now have to look up their roles list individually.
                            IList<string> userRoles = await _userManager.GetRolesAsync(user);
                            userObject.Roles = userRoles;

                            userObject.Id = user.Id;
                            userObject.Email = user.Email;
                            userObject.EmailVerified = user.EmailConfirmed;
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
                            userObject.AccountLocked = false;
                            userObject.LastLogin = user.LastLogin;
                            userObject.RegistrationDate = user.RegistrationDate;

                            // Account Lockout?
                            // userObject.AccountLocked = user.LockoutEnabled;
                            // It's not that easy! LockoutEnabled is always true and it means the user CAN be locked out!
                            // The LockoutEndDateUtc field is the UTC dateTime of when th euser is locked out to.
                            // So you'd need to check if that date is greater than the current date (locked out) or not (unlocked)
                            // You could allow the admin to enter a date time the user is locked out to? hours/days/months/years?
                            // Out of scope really. Just delete the user or reset their password!

                            // Add the user to the DTO list
                            pagedUserList.Add(userObject);
                        }

                        // Add the GetUserDto list to the GetPagedUsersDto Data section.
                        Data.Users = pagedUserList;

                        // Add the DTOS to the service response.
                        response.Data = Data;

                        // Success
                        response.Success = true;
                        response.Message = "Success!";
                        return response;
                    }

                    // The user wasn't an admin and tried to acces the user list
                    // Get their username from the JWT cookie in the http session.
                    userName = GetUserName();

                    // Send a message to tell user of the error
                    response.Success = false;
                    response.Message = "Unknown Request OR You are NOT an admin user.";

                    _logger.LogInformation("ApiVersion: {ApiVersion} - Unknown page index OR Non admin user tried to access user records. AdminController.GetPagedUsers - USER: {1}", version, userName);
                    return NotFound();
                }

                // The user wasn't an admin and tried to acces the user list
                // Get their username from the JWT cookie in the http session.
                userName = GetUserName();

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.RegisterAdmin - USER: {1}", version, userName);
                return NotFound();

            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.GetPagedUsers - {1}", version, ex.Message);

                return NotFound();
            }

        }


        // Get A User by UserName
        // yoursite.com/Secret/Admin/GetUserByUsername
        [Authorize(Roles = "AppAdmin")]
        [HttpGet]
        [Route("GetUserByUsername/{username}")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> GetUserByUsername(string username, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<GetUserDto>();
                int passValidation = _validate.alphabetValidation(username);
                string userName = String.Empty;

                if (passValidation == 0)
                {

                    // Check if the user role is "admin" ? [true] Get user : [false] return null
                    /*
                    AppUser user =
                     GetUserRoles().Contains("AppAdmin") ?
                    await _subModule.GetUserByEmailOrUserName(username) : null;
                    */

                    // We could use the normal GetUserByEmailOrUserName() module we have been using in register and Login
                    // However, it won't allow a "search" - the username will have to match exactly.
                    // The linq statement .Contains() means if we enter a partial username "mike" instead of "mike12" we will still get a result.
                    // Only 1 result though, as we are using FirstOrDefaultAsync()

                    AppUser user =
                    GetUserRoles().Contains("AppAdmin") ?
                        await _context.Users.FirstOrDefaultAsync(c => c.UserName.Contains(username)) : null;

                    if (user != null)
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
                        userObject.EmailVerified = user.EmailConfirmed;
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
                        userObject.AccountLocked = user.LockoutEnabled;
                        userObject.LastLogin = user.LastLogin;
                        userObject.RegistrationDate = user.RegistrationDate;


                        // Add the GetUserDto to the service response.
                        response.Data = userObject;

                        // Success
                        response.Success = true;
                        response.Message = "Success!";
                        return response;
                    }
                    else
                    {

                        // No match for the username/email in our database.
                        response.Success = false;
                        response.Message = "Unknown username, couldn't find that user.";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - Unknown username, couldn't find that user. AdminController.GetUserByUsername - USER: {1} Searched for: {2}", version, userName, username);
                        return BadRequest(response);
                    }
                }

                // The user wasn't an admin and tried to acces the user list
                // Get their username from the JWT cookie in the http session.
                userName = GetUserName();

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.GetUserByUsername - USER: {1} Searched for: {2}", version, userName, username);
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.GetUserByUsername - {1}", version, ex.Message);

                return NotFound();
            }
        }


        // Get A User by Email
        // yoursite.com/Secret/Admin/GetUserByEmail
        [Authorize(Roles = "AppAdmin")]
        [HttpGet]
        [Route("GetUserByEmail/{email}")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> GetUserByEmail(string email, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<GetUserDto>();
                int passValidation = _validate.alphabetValidation(email);
                string userName = String.Empty;

                if (passValidation == 0)
                {

                    // Check if the user role is "admin" ? [true] Get user : [false] return null

                    AppUser user =
                    GetUserRoles().Contains("AppAdmin") ?
                        await _context.Users.FirstOrDefaultAsync(c => c.Email.Contains(email)) : null;

                    if (user != null)
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
                        userObject.EmailVerified = user.EmailConfirmed;
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
                        userObject.AccountLocked = user.LockoutEnabled;
                        userObject.LastLogin = user.LastLogin;
                        userObject.RegistrationDate = user.RegistrationDate;


                        // Add the GetUserDto to the service response.
                        response.Data = userObject;

                        // Success
                        response.Success = true;
                        response.Message = "Success!";
                        return response;
                    }
                    else
                    {
                        // No match for the username/email in our database.
                        response.Success = false;
                        response.Message = "Unknown email address, couldn't find that user.";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - Unknown email address, couldn't find that user. AdminController.GetUserByEmail - USER: {1} Searched for: {2}", version, userName, email);
                        return BadRequest(response);
                    }
                }

                // The user wasn't an admin and tried to acces the user list
                // Get their username from the JWT cookie in the http session.
                userName = GetUserName();

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.GetUserByEmail - Searched for: {2}", version, userName, email);
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.GetUserByEmail - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // Get A User by Id
        // Admin area allows search by User Id
        // yoursite.com/Secret/Admin/GetUserById
        [Authorize(Roles = "AppAdmin")]
        [HttpGet]
        [Route("GetUserById/{userId}")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> GetUserById(string userId, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<GetUserDto>();
                int passValidation = _validate.alphabetValidation(userId);
                string userName = String.Empty;

                if (passValidation == 0)
                {

                    // Check if the user role is "admin" ? [true] Get user : [false] return null
                    AppUser user =
                     GetUserRoles().Contains("AppAdmin") ?
                    await _userManager.FindByIdAsync(userId) : null;

                    if (user != null)
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
                        userObject.EmailVerified = user.EmailConfirmed;
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
                        userObject.AccountLocked = user.LockoutEnabled;
                        userObject.LastLogin = user.LastLogin;
                        userObject.RegistrationDate = user.RegistrationDate;


                        // Add the GetUserDto to the service response.
                        response.Data = userObject;

                        // Success
                        response.Success = true;
                        response.Message = "Success!";
                        return response;
                    }
                    else
                    {
                        // No match for the username/email in our database.
                        response.Success = false;
                        response.Message = "Unknown Id, couldn't find that user.";

                        _logger.LogInformation("ApiVersion: {ApiVersion} - Unknown Id, couldn't find that user. AdminController.GetUserById - USER: {1}", version, userName);
                        return BadRequest(response);
                    }
                }

                // The user wasn't an admin and tried to acces the user list
                // Get their username from the JWT cookie in the http session.
                userName = GetUserName();

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.GetUserById - USER: {1}", version, userName);
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.GetUserById - {1}", version, ex.Message);

                return NotFound();
            }
        }





        // ADD USER
        // yoursite.com/Secret/Admin/AddUser
        [Authorize(Roles = "AppAdmin")]
        [HttpPost]
        [Route("AddUser")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> AddUser(AdminAddUserDto request, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<List<GetUserDto>>();

                int passValidation = _validate.emailValidation(request.Email) + _validate.alphabetValidation(request.UserName) +
                    _validate.alphabetValidation(request.Password) + _validate.alphabetValidation(request.GivenName) + _validate.alphabetValidation(request.FamilyName)
                    + _validate.alphabetValidation(request.AddressNumber) + _validate.alphabetValidation(request.AddressLine1) + _validate.alphabetValidation(request.AddressLine2)
                    + _validate.alphabetValidation(request.City) + _validate.alphabetValidation(request.State) + _validate.alphabetValidation(request.Country) + _validate.alphabetValidation(request.PostCode)
                    + _validate.alphabetValidation(request.Language) + _validate.alphabetValidation(request.Timezone) + _validate.alphabetValidation(request.Role);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {

                    // Check if the user role is "admin" ? [true] Get user : [false] return null
                    AppUser userEmailExists =
                        GetUserRoles().Contains("AppAdmin") ?
                        await _subModule.GetUserByEmailOrUserName(request.Email) : null;

                    AppUser userNameExists =
                        GetUserRoles().Contains("AppAdmin") ?
                        await _subModule.GetUserByEmailOrUserName(request.UserName) : null;


                    // We need the user's email and username to be unique!

                    if (userEmailExists != null)
                    {
                        response.Success = false;
                        response.Message = "User Email Already Exists!";
                        _logger.LogInformation("ApiVersion: {ApiVersion} - User Email Already Exists! AdminController.AddUser - USER: {1} - EMAIL: {2}", version, request.UserName, request.Email);
                        return StatusCode(StatusCodes.Status500InternalServerError, response);
                    }

                    if (userNameExists != null)
                    {
                        response.Success = false;
                        response.Message = "UserName Already Exists!";
                        _logger.LogInformation("ApiVersion: {ApiVersion} - UserName Already Exists! AdminController.AddUser - USER: {1} - EMAIL: {2}", version, request.UserName, request.Email);
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
                        // Success

                        // All users have the AppBasic role in the roles list
                        await _userManager.AddToRoleAsync(user, "AppBasic");

                        // The admin can choose to add the Premium users role to the role list as well
                        if (request.Role == "AppPremium")
                        {
                            await _userManager.AddToRoleAsync(user, "AppPremium");
                        }

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

                    response.Success = false;
                    response.Message = "Failed To Create User. Check Password Meets Standards.";
                    _logger.LogInformation("ApiVersion: {ApiVersion} - Failed To Create User in AdminController.AddUser - USER: {1} - EMAIL: {2} - Errors: {3}", version, request.UserName, request.Email, createUser.Errors);
                    return BadRequest(response);
                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.AddUser - USER: {1} ", version, request.UserName);

                return BadRequest(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.AddUser - {1}", version, ex.Message);

                return NotFound();
            }
        }



        // DELETE USER
        // yoursite.com/Secret/Admin/DeleteUser
        [Authorize(Roles = "AppAdmin")]
        [HttpDelete]
        [Route("DeleteUser/{userId}")]
        public async Task<ActionResult<ServiceResponse<GetUserDto>>> DeleteUser(string userId, ApiVersion version)
        {
            try
            {
                var response = new ServiceResponse<List<GetUserDto>>();

                int passValidation = _validate.alphabetValidation(userId);

                // 0 is a pass, 1+ is a fail.
                if (passValidation == 0)
                {

                    // Check if the user role is "admin" ? [true] Get user : [false] return null
                    AppUser user =
                     GetUserRoles().Contains("AppAdmin") ? await _userManager.FindByIdAsync(userId) : null;


                    if (user != null)
                    {
                        // Don't allow deletion of default admin user!
                        if (user.UserName != "admin")
                        {
                            // Delete the user
                            var deleteUser = await _userManager.DeleteAsync(user);

                            // The admin can choose to add the Premium users role to the role list as well
                            if (deleteUser.Succeeded)
                            {
                                response.Success = true;
                                response.Message = "Success!";
                                return Ok(response);
                            }

                            response.Success = false;
                            response.Message = "User Delete Failed.";
                            _logger.LogInformation("ApiVersion: {ApiVersion} - Failed to delete user in AdminController.DeleteUser - USER: {0} - EMAIL: {1} - Errors: {2}", version, user.UserName, user.Email, deleteUser.Errors);
                            return NotFound(response);
                        }
                        else
                        {
                            response.Success = false;
                            response.Message = "Can't delete default admin!";
                            _logger.LogInformation("ApiVersion: {ApiVersion} - Tried to delete default admin user in AdminController.DeleteUser - USER: {0} - EMAIL: {1}", version, user.UserName, user.Email);
                            return NotFound(response);
                        }

                    }

                    response.Success = false;
                    response.Message = "Couldn't find user.";
                    _logger.LogInformation("ApiVersion: {ApiVersion} - Failed To Find User in AdminController.DeleteUser - ID: {0}", version, userId);
                    return BadRequest(response);
                }

                // Send a message to tell user of the error
                response.Success = false;
                response.Message = "Validation Failed.";

                _logger.LogInformation("ApiVersion: {ApiVersion} - Validation Failed in AdminController.DeleteUser - ID: {0}", version, userId);

                return BadRequest(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("ApiVersion: {ApiVersion} - Exception in AdminController.DeleteUser - {0}", version, ex.Message);

                return NotFound();
            }
        }






        // SUB-MODULES


        // GET THE USER ID FROM THE CURRENT HTTP SESSION
        // User has logged in, so we can use HttpContextAccessor to grab to user's ID from the JWT token.
        // ClaimTypes.NameIdentifier gives the current user id, and ClaimTypes.Name gives the username.
        private string GetUserName() => _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);

        private IEnumerable<string> GetUserRoles() => _httpContextAccessor.HttpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value);


    }
}
