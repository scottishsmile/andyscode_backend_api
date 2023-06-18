using API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace API.Data
{
    public class AppDbContext : IdentityDbContext<AppUser, IdentityRole, string>
    {

        /*
            cd "C:\CSharpProjects\1 - dotnet7\Portfolio Web App\Identity Core API"

            You NEED to make sure appsettings.Development.json has the MySQL connection string!
            It won't work with the Local version.
        
            project> dotnet tool install --global dotnet-ef
                 or 
            project> dotnet tool update --global dotnet-ef --version 7.0.5

            project> dotnet ef migrations add InitialCreate --project API
            project> dotnet ef database update --project API


         */


        // Refresh Token Pruning
        // mysql > select count(*) from RefreshTokenTable
        // then
        //          mysql> delete from RefreshTokenTable where DateTokenIssued < now() - interval 8 DAY
        // or
        //          mysql> delete from RefreshTokenTable where DateTokenExpires < now() - interval 8 DAY
        // check rows again
        // mysql > select count(*) from RefreshTokenTable

        // https://stackoverflow.com/questions/62485906/how-to-add-tables-and-relations-to-generated-asp-net-core-mvc-identity-database
        public DbSet<RefreshTokenTable> RefreshTokenTable { get; set; }
        public DbSet<MfaCodeTable> MfaCodeTable { get; set; }
        public DbSet<MfaTokenTable> MfaTokenTable { get; set; }


        public AppDbContext(DbContextOptions options)
            : base(options)
        {
        }

    }
}