using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Text;
using Serilog;
using Serilog.Sinks.Map;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using API;
using API.Data;
using API.Models;
using API.Factories;
using API.Models.v1_0;
using API.Controllers.v1_0.SubModules;
using API.Services.v1_0;
using API.Services.v1_0.Newsletter;
using API.Services.v1_0.EmailService;
using API.Validation.v1_0;
using API.Models.v2_0;
using API.Controllers.v2_0.SubModules;
using API.Services.v2_0;
using API.Services.v2_0.Newsletter;
using API.Services.v2_0.EmailService;
using API.Validation.v2_0;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Serilog.Events;
using Serilog.Formatting.Compact;
using System.Reflection;
using API.Services;
using Microsoft.AspNetCore.HttpOverrides;           // NGINX or Apache reverse proxy header.
using System.Net;
using API.Services.v2_0.MyMFA;



// CORS
var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";

try
{
    Log.Information("API Booting...");
    Debug.WriteLine("API Booting...");
    Console.WriteLine("API Booting...");        // Leave this in incase serilog doesn't load on bootup.

    var builder = WebApplication.CreateBuilder(args);

    // Production Kestrel Server launch urls.
    builder.WebHost.UseUrls("https://localhost:5001");

    // Get config from appsettings.json
    var configuration = new ConfigurationBuilder()
        .AddEnvironmentVariables()
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)     // Use appsettings.Local.json or apsettings.Development.json configured in launchSettings.json
        .AddJsonFile("hostsettings.json", optional: true)
        .AddEnvironmentVariables()
        .Build();


    // Serilog Logging
    var basePath = AppContext.BaseDirectory;
    Debug.WriteLine($"Logs Base Directory is {basePath}/Logs");

    // Serilog write to different folder locations depending on versions
    // The folder has to be created beforehand!
    var logger = new LoggerConfiguration().WriteTo.Map(
            "ApiVersion",
            "LogsWithoutVersions",
            (ApiV, wt) =>
                wt.File(new CompactJsonFormatter(), $"{basePath}/Logs/{ApiV}/apiLog-.json", rollingInterval: RollingInterval.Day)
            )
      .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Verbose)                     // Log everything, Verbose is lowest level. Verbose, Debug, Information, Warning, Error and Fatal
      .ReadFrom.Configuration(builder.Configuration)
      .Enrich.FromLogContext()
      .CreateLogger();

    // Logging
    builder.Logging.ClearProviders();
    builder.Logging.AddSerilog(logger);

    // Load settings from appsettings.json
    builder.Services.Configure<SeedUsersConfig>(configuration.GetSection("SeedUsersConfiguration"));
    builder.Services.Configure<EmailConfigV1>(configuration.GetSection("EmailConfiguration"));
    builder.Services.Configure<SendInBlueConfigV1>(configuration.GetSection("SendInBlueConfiguartion"));
    builder.Services.Configure<EmailConfigV2>(configuration.GetSection("EmailConfiguration"));
    builder.Services.Configure<SendInBlueConfigV2>(configuration.GetSection("SendInBlueConfiguartion"));
    builder.Services.Configure<MyMFASettings>(configuration.GetSection("MyMFASettings"));


    // Dependancy Injection
    builder.Services.AddTransient<IValidateV1, ValidateV1>();
    builder.Services.AddTransient<IValidateV2, ValidateV2>();
    builder.Services.AddTransient<INewsletterV1, NewsletterV1>();
    builder.Services.AddTransient<IEmailServiceV1, EmailServiceV1>();
    builder.Services.AddScoped<IControllerSubModulesV1, ControllerSubModulesV1>();              // Can't be Transient or App won't start.
    builder.Services.AddTransient<INewsletterV2, NewsletterV2>();
    builder.Services.AddTransient<IEmailServiceV2, EmailServiceV2>();
    builder.Services.AddScoped<IControllerSubModulesV2, ControllerSubModulesV2>();              // Can't be Transient or App won't start.
    builder.Services.AddTransient<IMyMFA, MyMFA>();


    // Nginx proxy forwarded headers
    var appSystemSettings = configuration.GetSection("AppSystemSettings");
    var proxies = appSystemSettings.Get<AppSystemSettings>();
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.KnownProxies.Add(IPAddress.Parse(proxies.ReverseProxy));
    });


    // Entity Database Context. 
    var connectionString = builder.Configuration.GetConnectionString("MySQLConnection");
    //var serverVersion = new MySqlServerVersion(new Version(8, 0, 30));
    // try auto detecting the server version instead...
    var serverVersion = ServerVersion.AutoDetect(connectionString);
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseMySql(connectionString, serverVersion));             // Using the MySQL Pomelo nuget, you need to tell it the version of MySql.
    builder.Services.AddDatabaseDeveloperPageExceptionFilter();


    // Configure Identity Core
    // This database will hold our user data!
    // AppUser is our custom User Class that extends the normal IdentityUser
    // We just use the standard IdentityRoles. Creating custom roles is essentially putting different table header into a single role. 
    // AppUserClaimsPrincipalFactory - We had to add our custom AppUser class to the JWT Claims.
    builder.Services.AddDefaultIdentity<AppUser>()
        .AddRoles<IdentityRole>()
        .AddClaimsPrincipalFactory<AppUserClaimsPrincipalFactory>()
        .AddDefaultTokenProviders()
        .AddEntityFrameworkStores<AppDbContext>();
    // More setup in app builder below....



    // JWT Tokens for Identity Core User Management.
    // Identity Core handles user register/login/logout
    var jwtSection = configuration.GetSection("JwtBearerTokenSettings");
    builder.Services.Configure<JwtBearerTokenSettings>(jwtSection);             // Token settings are a Model so we can grab it from appsettings.json
    var jwtBearerTokenSettings = jwtSection.Get<JwtBearerTokenSettings>();
    var key = Encoding.ASCII.GetBytes(jwtBearerTokenSettings.AccessTokenSecretKey);

    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
       .AddJwtBearer(options =>
       {
           options.RequireHttpsMetadata = false;
           options.SaveToken = true;
           options.TokenValidationParameters = new TokenValidationParameters()
           {
               // This is also duplicated to validate Refresh Tokens in ControllerSubModules.ValidateRefreshToken()
               // Only difference is that it uses RefreshTokenSecretKey
               // Make the same changes in both places.
               ValidateIssuer = false,                                                 // Maybe set to true for production?
               ValidIssuer = jwtBearerTokenSettings.Issuer,
               ValidateAudience = false,                                               // Maybe set to true for production?
               ValidAudience = jwtBearerTokenSettings.Audience,
               ValidateIssuerSigningKey = true,
               IssuerSigningKey = new SymmetricSecurityKey(key),                       // AccessTokenSecretKey used here
               ValidateLifetime = true,
               ClockSkew = TimeSpan.Zero
           };
       });

    // Identity Core Fine Grained Policies
    builder.Services.Configure<IdentityOptions>(options =>
    {
        // Email Verification
        options.SignIn.RequireConfirmedEmail = true;
        options.User.RequireUniqueEmail = true;
        // Lockout Settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
        // Default Password settings.
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 6;
        options.Password.RequiredUniqueChars = 1;

    });

    // Identity Email Token Settings (Confirm email / reset pass)
    builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
        opt.TokenLifespan = TimeSpan.FromHours(2));

    // Index page for production use.
    builder.Services.AddControllersWithViews();


    // Versioning
    builder.Services.AddApiVersioning(opt =>
    {
        opt.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(2, 0);                              // Default Version is v2.0
        opt.AssumeDefaultVersionWhenUnspecified = true;                                                     // Useful for migrating an API without versioning to supporting versioning. No Version number supplied? Assume v1.0.
        opt.ReportApiVersions = true;                                                                       // The API broadcasts what versions are available. "api-supported-versions: 1.0, 2.0".

        // The basic way versioning works is to add a query string to your url. "?api-version=1.0"
        // GET www.mysite.com/controller?api-version=1.0
        // Lets configure some additional, more robust and eaiser options to supply the version number.
        opt.ApiVersionReader = ApiVersionReader.Combine(new UrlSegmentApiVersionReader(),                   // Get version number  from URL. "www.mysite.com/v1/controller"
                                                        new HeaderApiVersionReader("api-version"),          // Get version number from a seperate request header. "api-version: 1.0"
                                                        new MediaTypeApiVersionReader("api-version"),       // Get version number from the Accept or Content-Type request headers. "Accept: application/json; api-version=1.0"
                                                        new QueryStringApiVersionReader("api-version"));    // Change the query string paramter name if you want to "?api-version=1.0"  GET www.mysite.com/api/controller?api-version=1.0
    });

    // Configure Swagger to show the API versions
    // Add ApiExplorer to discover versions
    builder.Services.AddVersionedApiExplorer(setup =>
    {
        setup.GroupNameFormat = "'v'VVV";
        setup.SubstituteApiVersionInUrl = true;
    });

    builder.Services.AddEndpointsApiExplorer();


    // Swagger
    builder.Services.AddSwaggerGen(options =>
    {
        options.AddSecurityDefinition(name: "Bearer", securityScheme: new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Description = "Please enter token. Include 'bearer' first. bearer xg2sty56...",
            In = ParameterLocation.Header,
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer"
        });
        options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type=ReferenceType.SecurityScheme,
                            Id="Bearer"
                        }
                    },
                    new string[]{}
                }
            });
    }
    );

    // Swagger Versioning options & dependancy injection
    builder.Services.ConfigureOptions<ConfigureSwaggerOptions>();


    // CORS
    builder.Services.AddCors(options =>
    {
        options.AddPolicy(name: MyAllowSpecificOrigins,
                          policy =>
                          {
                              policy.WithOrigins(Constants.Cors.urls).AllowAnyHeader().AllowAnyMethod();
                          });
    });




    var app = builder.Build();

    // Nginx proxy forwarded headers
    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    });

    // Identity Core Set Up
    // https://www.youtube.com/watch?v=ZTjGwat5mro
    // .Net 5 allowd you to create UserManger and RoleManger in ConfigureServices() in Startup.cs
    // .Net 6 uses this service provider method instead.
    var scopeFactory = app.Services.GetRequiredService<IServiceScopeFactory>();
    using (var scope = scopeFactory.CreateScope())
    {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var seedUserLogger = scope.ServiceProvider.GetRequiredService<ILogger<SeedUserService>>();
        var seedUserConfig = scope.ServiceProvider.GetRequiredService<IOptions<SeedUsersConfig>>();

        SeedUserService seeding = new SeedUserService(seedUserLogger, seedUserConfig, userManager, roleManager);

        // Create Identity Roles
        await seeding.CreateRoles();

        // Seed Database with Default Admin User
        await seeding.SeedAdmin();

        // Seed Database with Test Users
        await seeding.SeedTestUsers();
    }

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }

    // Environemnt Specific Settings

    if (app.Environment.EnvironmentName == "Local")
    {
        Debug.WriteLine("Environment is LOCAL");
        Console.WriteLine("Environment is LOCAL");        // Leave this in incase serilog doesn't load on bootup.

        app.UseMigrationsEndPoint();
        app.UseSwagger();                           // Swagger only in dev mode.
        app.UseSwaggerUI(options =>
        {
            // Swagger Version Dropdown

            var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();                          // Used in Swagger with Versioning

            // The ".Reverse()" will show the latest version first in swagger!
            foreach (var description in provider.ApiVersionDescriptions.Reverse())
            {
                // Swagger with Versioning
                options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json", description.GroupName.ToUpperInvariant());
            }

            options.RoutePrefix = string.Empty;
        });
    }

    if (app.Environment.EnvironmentName == "Development")
    {
        Debug.WriteLine("Environment is DEVELOPMENT");
        Console.WriteLine("Environment is DEVELOPMENT");        // Leave this in incase serilog doesn't load on bootup.

        app.UseMigrationsEndPoint();
        app.UseSwagger();                           // Swagger only in dev mode.
        app.UseSwaggerUI(options =>
        {
            // Swagger Version Dropdown

            var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();                          // Used in Swagger with Versioning

            // The ".Reverse()" will show the latest version first in swagger!
            foreach (var description in provider.ApiVersionDescriptions.Reverse())
            {
                // Swagger with Versioning
                options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json", description.GroupName.ToUpperInvariant());
            }

            options.RoutePrefix = string.Empty;
        });
    }

    if (app.Environment.EnvironmentName == "Production")
    {
        Debug.WriteLine("Environment is PRODUCTION");
        Console.WriteLine("Environment is PRODUCTION");        // Leave this in incase serilog doesn't load on bootup.

        // No Swagger in production!
        // Use index page instead.
        // URL Routes
        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Index}/{action=IndexPage}");
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();

    app.UseCors(MyAllowSpecificOrigins);            // CORS

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapRazorPages();
    app.MapControllers();


    // Run the App
    Log.Information("API Starting Up...");
    app.Run();
}
catch (Exception ex)
{
    string type = ex.GetType().Name;
    if (type.Equals("StopTheHostException", StringComparison.Ordinal))
    {
        // Entity Framework exception https://github.com/dotnet/runtime/issues/60600
        //     Error! Identity Server Failed To Start!
        //     Exception of type 'Microsoft.Extensions.Hosting.HostFactoryResolver+HostingListener+StopTheHostException' was thrown.
        throw;
    }
    else
    {
        Log.Fatal("Error! API Failed To Start! - " + ex.Message);
        Console.WriteLine("Error! API Failed To Start! - " + ex.Message);        // Leave this in incase serilog doesn't load on bootup.
    }

}
finally
{
    // Clean up code and write log to file
    Log.CloseAndFlush();
}