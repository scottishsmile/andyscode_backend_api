namespace API.Models.v2_0
{
    public class SendInBlueConfigV2
    {
        public string apiKey { get; set; }

        public int ListId { get; set; }             // The List Id to be subscribed to. Brevo.com > Contacts > Lists
    }
}
