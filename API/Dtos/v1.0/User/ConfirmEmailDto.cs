namespace API.Dtos.v1_0.User
{
    public class ConfirmEmailDto
    {
        public string Token { get; set; }               // Emailed Confirmation Token
        
        public string UserName { get; set; }

    }
}
