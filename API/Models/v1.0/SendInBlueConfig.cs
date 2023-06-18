namespace API.Models.v1_0
{
    public class SendInBlueConfigV1
    {
        public string apiKey { get; set; }

        public int ListId { get; set; }             // The List Id to be subscribed to. Brevo.com > Contacts > Lists
    }
}
