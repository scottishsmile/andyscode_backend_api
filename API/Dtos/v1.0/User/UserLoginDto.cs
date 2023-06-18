namespace API.Dtos.v1_0.User
{
    public class UserLoginDto
    {
        public string UserName { get; set; }            // Can be username or email address.
        public string Password { get; set; }
    }
}
