
namespace API.Models.v2_0
{
    public class EmailConfigV2
    {

        // This is used to load the details from appsettings.json so they can be used in EmailService.cs
        // That way we only have to update the config file to change the SMTP server.
        public string AdminEmailAddress { get; set; }
        public string SmtpServer { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUsername { get; set; }
        public string SmtpPassword { get; set; }
        public string ApiUrl { get; set;  }
        public string AdminWebsiteUrl { get; set; }
        public string FrontEndWebsiteUrl { get; set; }
        public string SiteTitle { get; set; }
        public string SiteName { get; set; }
    }
}
