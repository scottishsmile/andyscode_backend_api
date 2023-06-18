

namespace API.Services.v2_0.EmailService
{
    public interface IEmailServiceV2
    {
       void SendEmail(string destination, string subject, string message);                // Send an email using the website host's SMTP server.

       void SendEmailToAdmin(string from, string subject, string message);
    }
}
