using API.Dtos.v1_0;
using API.Models;
using API.Models.v1_0;

namespace API.Services.v1_0.Newsletter
{
    public interface INewsletterV1
    {
        Task<ServiceResponse<string>> Subscribe(AppUser user);            // After Email validation, subscibe user to newsletter.
    }
}
