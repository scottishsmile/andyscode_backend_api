namespace API.Models
{
    public class JwtBearerTokenSettings
    {
        // A Model so we can grab JWT settings from appsettings.json

        public string? AccessTokenSecretKey { get; set; }
        public string? RefreshTokenSecretKey { get; set; }
        public string? MfaTokenSecretKey { get; set; }
        public string? Audience { get; set; }
        public string? Issuer { get; set; }
        public int AccessTokenExpiryTimeInMinutes { get; set; }
        public int RefreshTokenExpiryTimeInMinutes { get; set; }
    }
}
