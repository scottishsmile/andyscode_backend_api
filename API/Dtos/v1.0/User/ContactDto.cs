namespace API.Dtos.v1_0.User
{
    public class ContactDto
    {
        public string UserName { get; set; } = "empty";         // Username so we can lookup their email address. Also so we are not sending their email address over the internet.
        public string Subject { get; set; } = "empty";
        public string Message { get; set; } = "empty";
    }
}
