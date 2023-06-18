using MailKit;                          // Send SMTP emails
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;                          // MIME email message format
using MimeKit.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using API.Models.v2_0;

namespace API.Services.v2_0.EmailService
{
    public class EmailServiceV2 : IEmailServiceV2
    {

        private readonly ILogger<EmailServiceV2> _logger;
        private readonly IOptions<EmailConfigV2> _emailConfig;                            // EmailConfiguration settings in appsettings.json

        // Constructor
        public EmailServiceV2(IOptions<EmailConfigV2> emailConfig, ILogger<EmailServiceV2>  logger)
        {
            _emailConfig = emailConfig;
            _logger = logger;
        }

        public void SendEmail(string destination, string subject, string message)
        {
            // Emails sent using MailKit
            // Multipurpose Internet Mail Extension (MIME) format. It allows us to send fancy emails containing attachements, video etc.

            // Uses "Email Configuration" settings inside appsettings.json
            // Use IOptions<IEmailConfig> _emailConfig.Value to access them.
            try {
                // Create Email
                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse(_emailConfig.Value.AdminEmailAddress));
                email.To.Add(MailboxAddress.Parse(destination));
                email.Subject = subject;
                email.Body = new TextPart(TextFormat.Html) { Text = message };


                // Send Email
                using var smtp = new SmtpClient();
                smtp.Connect(_emailConfig.Value.SmtpServer, _emailConfig.Value.SmtpPort);         // This can also be added - SecureSocketOptions.Auto - Allow the IMailService to decide which SSL or TLS options to use. Could also be SecureSocketOptions.SslOnConnect or SecureSocketOptions.StartTls.
                smtp.Authenticate(_emailConfig.Value.SmtpUsername, _emailConfig.Value.SmtpPassword);
                smtp.Send(email);
                smtp.Disconnect(true);
            }
            catch (Exception ex)
            {
                _logger.LogError("{Time} -SMTP Error in EmailService.SendEmail . Likely the SMTP server is misconfigured or firewall is blocking comms. Error - {1}", DateTime.UtcNow, ex.Message);

            }
        }


        public void SendEmailToAdmin(string from, string subject, string message)
        {
            // Emails sent using MailKit
            // Multipurpose Internet Mail Extension (MIME) format. It allows us to send fancy emails containing attachements, video etc.

            // Uses "Email Configuration" settings inside appsettings.json
            // Use IOptions<IEmailConfig> _emailConfig.Value to access them.
            try
            {
                // Create Email
                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse(from));
                email.To.Add(MailboxAddress.Parse(_emailConfig.Value.AdminEmailAddress));
                email.Subject = subject;
                email.Body = new TextPart(TextFormat.Html) { Text = message };


                // Send Email
                using var smtp = new SmtpClient();
                smtp.Connect(_emailConfig.Value.SmtpServer, _emailConfig.Value.SmtpPort);         // This can also be added - SecureSocketOptions.Auto - Allow the IMailService to decide which SSL or TLS options to use. Could also be SecureSocketOptions.SslOnConnect or SecureSocketOptions.StartTls.
                smtp.Authenticate(_emailConfig.Value.SmtpUsername, _emailConfig.Value.SmtpPassword);
                smtp.Send(email);
                smtp.Disconnect(true);
            }
            catch (Exception ex)
            {
                _logger.LogError("{Time} -SMTP Error in EmailService.SendEmail . Likely the SMTP server is misconfigured or firewall is blocking comms. Error - {1}", DateTime.UtcNow, ex.Message);

            }
        }

    }
}
