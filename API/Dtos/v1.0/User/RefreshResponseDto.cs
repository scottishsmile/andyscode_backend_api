namespace API.Dtos.v1_0.User
{
    public class RefreshResponseDto
    {
        // Access tokens allow Access to the app and are only available for a short amount of time, minutes.
        // A refresh token lasts much longer, days.
        // You can use the refresh token to get a new access token when the client is started! Without having to login again!
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpiry { get; set; }
    }
}
