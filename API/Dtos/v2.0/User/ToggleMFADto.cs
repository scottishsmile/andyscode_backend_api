namespace API.Dtos.v2_0.User
{
    public class ToggleMFADto
    {
        public string UserName { get; set; } = "empty";

        public bool MfaSwitch { get; set; } = false;
    }
}
