
using API.Dtos.v2_0;
using API.Models;
using API.Models.v2_0;

namespace API.Services.v2_0.Newsletter
{
    public interface INewsletterV2
    {
        Task<ServiceResponse<string>> Subscribe(AppUser user);            // After Email validation, subscibe user to newsletter.
    }
}
