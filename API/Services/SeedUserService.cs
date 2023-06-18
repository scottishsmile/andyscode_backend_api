using API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using static API.Constants;

namespace API.Services
{
    public class SeedUserService
    {

        private UserManager<AppUser> _userManager;
        private RoleManager<IdentityRole> _roleManager;
        private ILogger<SeedUserService> _logger;
        private IOptions<SeedUsersConfig> _seedUserConfig;

        public SeedUserService(ILogger<SeedUserService> logger, IOptions<SeedUsersConfig> seedUserConfig, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _logger = logger;
            _seedUserConfig = seedUserConfig;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task CreateRoles()
        {
            try
            {
                // Create Identity Roles
                // Use this method NOT a class of IdentityRole : AppRoles  it doesn't work. That's to make each role have sub properties.

                // Check if role exists
                bool appBasicExists = await _roleManager.RoleExistsAsync("AppBasic");

                if (!appBasicExists)
                {
                    // Create AppBasic Role
                    var role = new IdentityRole();
                    role.Name = "AppBasic";
                    await _roleManager.CreateAsync(role);
                    _logger.LogInformation("AppBasic Role Created. SeedUserService.cs");
                }
                else
                {
                    _logger.LogInformation("AppBasic Role Already Exists. SeedUserService.cs");
                }


                bool appPremiumExists = await _roleManager.RoleExistsAsync("AppPremium");

                if (!appPremiumExists)
                {
                    // Create AppPremium Role
                    var role = new IdentityRole();
                    role.Name = "AppPremium";
                    await _roleManager.CreateAsync(role);
                    _logger.LogInformation("AppPremium Role Created. SeedUserService.cs");
                }
                else
                {
                    _logger.LogInformation("AppPremium Role Already Exists. SeedUserService.cs");
                }


                bool appAdminExists = await _roleManager.RoleExistsAsync("AppAdmin");

                if (!appAdminExists)
                {
                    // Create AppAdmin Role
                    var role = new IdentityRole();
                    role.Name = "AppAdmin";
                    await _roleManager.CreateAsync(role);
                    _logger.LogInformation("AppAdmin Role Created. SeedUserService.cs");
                }
                else
                {
                    _logger.LogInformation("AppAdmin Role Already Exists. SeedUserService.cs");
                }
            }
            catch (Exception ex)
            {
                _logger.LogInformation("Error in CreateRoles.SeedUserService.cs - " + ex);
            }
        }



        // Create the default admin user when program starts
        public async Task SeedAdmin()
        {
            try
            {
                // Find the user with the admin email 
                string adminEmail = _seedUserConfig.Value.Email;
                var adminUser = await _userManager.FindByEmailAsync(adminEmail);

                // Does Admin already exist?
                if (adminUser == null)
                {
                    // Create Admin User
                    var admin = new AppUser
                    {
                        UserName = _seedUserConfig.Value.UserName,
                        Email = _seedUserConfig.Value.Email,
                        EmailConfirmed = true,
                        GivenName = _seedUserConfig.Value.GivenName,
                        FamilyName = _seedUserConfig.Value.FamilyName,
                        AddressNumber = _seedUserConfig.Value.AddressNumber,
                        AddressLine1 = _seedUserConfig.Value.AddressLine1,
                        AddressLine2 = _seedUserConfig.Value.AddressLine2,
                        City = _seedUserConfig.Value.City,
                        State = _seedUserConfig.Value.State,
                        Country = _seedUserConfig.Value.Country,
                        PostCode = _seedUserConfig.Value.PostCode,
                        Language = _seedUserConfig.Value.Language,
                        Timezone = _seedUserConfig.Value.Timezone,
                        LastLogin = DateTime.UtcNow,
                        RegistrationDate = DateTime.UtcNow,
                        EnableMFA = true
    };

                    // Use the SeedUsersConfigration password in appsettings.json
                    string adminPassword = _seedUserConfig.Value.Password;

                    var createAdminUser = await _userManager.CreateAsync(admin, adminPassword);
                    if (createAdminUser.Succeeded)
                    {
                        // Add role of AppAdmin to the user
                        await _userManager.AddToRoleAsync(admin, "AppAdmin");
                        _logger.LogInformation("Default Admin User Created. SeedUserService.cs");
                    }
                }
                else
                {
                    _logger.LogInformation("Default Admin User Already Exists. SeedUserService.cs");
                }
            }
            catch (Exception ex)
            {
                _logger.LogInformation("Error in SeedAdmin.SeedUserService.cs - " + ex);
            }
        }



        // Create Test Users
        public async Task SeedTestUsers()
        {
            try
            {
                // Test Users
                var user1 = new AppUser
                {
                    UserName = "davetest",
                    Email = "dave.test@test5589.com",
                    EmailConfirmed = true,
                    GivenName = "dave",
                    FamilyName = "smith",
                    AddressNumber = "9B",
                    AddressLine1 = "Test Ave",
                    AddressLine2 = "empty",
                    City = "Perth",
                    State = "WA",
                    Country = "Australia",
                    PostCode = "6000",
                    Language = "english",
                    Timezone = "(UTC+08:00) Perth",
                    LastLogin = DateTime.UtcNow,
                    RegistrationDate = DateTime.UtcNow
                };

                var user2 = new AppUser
                {
                    UserName = "sallytest",
                    Email = "sally.test@test5589.com",
                    EmailConfirmed = true,
                    GivenName = "sally",
                    FamilyName = "smith",
                    AddressNumber = "500",
                    AddressLine1 = "Test Lane",
                    AddressLine2 = "empty",
                    City = "Philadelphia",
                    State = "PA",
                    Country = "United States",
                    PostCode = "19119",
                    Language = "english",
                    Timezone = "(UTC-05:00) Eastern Time (US & Canada)",
                    LastLogin = DateTime.UtcNow,
                    RegistrationDate = DateTime.UtcNow
                };


                // Do the test users already exist?
                var user1Exists = await _userManager.FindByNameAsync(user1.UserName);
                var user2Exists = await _userManager.FindByNameAsync(user1.UserName);


                if (user1Exists == null)
                {
                    // Create User1

                    string user1Password = "BlueSky42!";

                    var createUser1 = await _userManager.CreateAsync(user1, user1Password);
                    if (createUser1.Succeeded)
                    {
                        // Add role of AppBasic to the user
                        await _userManager.AddToRoleAsync(user1, "AppBasic");
                        _logger.LogInformation("Test User1 Created. SeedUserService.cs");
                    }
                }

                if (user2Exists == null)
                {
                    // Create User2

                    string user2Password = "BlueSky42!";

                    var createUser2 = await _userManager.CreateAsync(user2, user2Password);
                    if (createUser2.Succeeded)
                    {
                        // Add role of AppPremium to the user
                        await _userManager.AddToRoleAsync(user2, "AppPremium");
                        _logger.LogInformation("Test User2 Created. SeedUserService.cs");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogInformation("Error in SeedTestUsers.SeedUserService.cs - " + ex);
            }
        }
    }
}
