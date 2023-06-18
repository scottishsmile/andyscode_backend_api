using sib_api_v3_sdk.Api;                       // Send In Blue Email Newsletter
using sib_api_v3_sdk.Client;                    // Send In Blue Email Newsletter
using sib_api_v3_sdk.Model;                     // Send In Blue Email Newsletter
using Microsoft.Extensions.Options;
using API.Models;
using API.Models.v2_0;
using API.Dtos.v2_0;
using Newtonsoft.Json.Linq;

namespace API.Services.v2_0.Newsletter
{
    public class NewsletterV2 : INewsletterV2
    {
        // SEND IN BLUE NEWSLETTER MODULE
        // Uses sib_api_v3_sdk library for SendInBlue API 3.3.0
        // https://github.com/sendinblue/APIv3-csharp-library


        private readonly ILogger<NewsletterV2> _logger;
        private readonly IOptions<SendInBlueConfigV2> _sibConfig;             // Get appsettings.json configs

        public NewsletterV2(ILogger<NewsletterV2> logger, IOptions<SendInBlueConfigV2> sibConfig)
        {
            _logger = logger;
            _sibConfig = sibConfig;
        }



        // SUBSCRIBE - CREATE CONTACT
        // The VerifyEmailDto contains th euser ID and the email verification token. We only need the ID to look up the user here.
        public async Task<ServiceResponse<string>> Subscribe(AppUser user)
        {
            var serviceResponse = new ServiceResponse<string>();

            try
            {
                    // Check the user wants to subscribe. Newsletter Checkbox checked.
                    if (user.Newsletter == true)
                    {
                        // Newsletter Subscription (SendInBlue)
                        // If Newsletter = true (a checkbox) then subscribe them
                        // Values are from appsettings.json config file
                        sib_api_v3_sdk.Client.Configuration.Default.ApiKey.Add("api-key", _sibConfig.Value.apiKey);

                        var apiInstance = new ContactsApi();
                        string email = user.Email;

                        JObject attributes = new JObject();
                        attributes.Add("LASTNAME", user.UserName);

                        // What Contacts List to subscribe to? They can be different for each email flow automation.
                        List<long?> listIds = new List<long?>();
                        listIds.Add(_sibConfig.Value.ListId);

                        bool emailBlacklisted = false;
                        bool smsBlacklisted = false;
                        bool updateEnabled = false;

                        try
                        {
                            var createContact = new CreateContact(email, attributes, emailBlacklisted, smsBlacklisted, listIds, updateEnabled);
                            CreateUpdateContactModel result = apiInstance.CreateContact(createContact);
                            _logger.LogInformation("SendInBlue Success - Newsletter.Subscribe - USER: {1} - EMAIL: {2} --- {3}", user.UserName, user.Email, result.ToJson());
                        }
                        catch (Exception ex)
                        {
                            _logger.LogInformation("SendInBlue Error - Newsletter.Subscribe - USER: {1} - EMAIL: {2} --- {3}", user.UserName, user.Email, ex.Message);
                        }
                    }
                    else
                    {
                        // User doesn't want to subscribe
                        serviceResponse.Success = false;
                        serviceResponse.Message = "User doesn't want to subscribe to newsletter.";
                        _logger.LogInformation("User doesn't want to subscribe to newsletter. Newsletter.Subscribe - UserName: {1}", user.UserName);
                    }
            }
            catch (Exception ex)
            {
                serviceResponse.Success = false;
                serviceResponse.Message = "Newsletter Subscription Error.";
                _logger.LogError("{Time} - Exception in Newsletter.Subscribe - {1}", DateTime.UtcNow, ex.Message);

            }

            return serviceResponse;
        }
    }
}
