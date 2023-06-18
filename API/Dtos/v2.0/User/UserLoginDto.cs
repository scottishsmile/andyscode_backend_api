namespace API.Dtos.v2_0.User
{
    public class UserLoginDto
    {
        public string UserName { get; set; }            // Can be username or email address.
        public string Password { get; set; }
        public string MfaCode { get; set; } = "empty";          // Default value of no MFA code supplied is "empty". This is checked in UserController.Login.
    }
}
