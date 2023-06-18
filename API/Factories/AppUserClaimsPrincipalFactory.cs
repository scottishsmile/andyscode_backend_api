using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using IdentityModel;
using API.Models;

namespace API.Factories
{
    public class AppUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<AppUser>
    {
        // As we have a custom user class AppUser, we need to make sure Identity adds it to the user claims.
        public AppUserClaimsPrincipalFactory(UserManager<AppUser> userManager, IOptions<IdentityOptions> optionsAccessor) : base(userManager, optionsAccessor)
        {

        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(AppUser user)
        {
            var claimsIdentity = await base.GenerateClaimsAsync(user);

            // Add our AppUser.cs custom properties to the claim.
            // The normal claim already has things like Id, Email etc.

            if (user.GivenName != null)
            {
                claimsIdentity.AddClaim(new Claim(JwtClaimTypes.GivenName, user.GivenName));
            }

            if (user.FamilyName != null)
            {
                claimsIdentity.AddClaim(new Claim(JwtClaimTypes.FamilyName, user.FamilyName));
            }

            if (user.Language != null)
            {
                claimsIdentity.AddClaim(new Claim("Language", user.Language));
            }

            if (user.Country != null)
            {
                claimsIdentity.AddClaim(new Claim("Country", user.Country.ToString()));
            }

            if (user.Timezone != null)
            {
                claimsIdentity.AddClaim(new Claim("Timezone", user.Timezone.ToString()));
            }

            return claimsIdentity;
        }
    }
}
