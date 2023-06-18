namespace API.Dtos.v2_0.User
{
    public class ChangePasswordDto
    {
        public string Token { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

    }
}
