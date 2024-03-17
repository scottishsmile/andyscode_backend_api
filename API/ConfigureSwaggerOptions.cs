using Asp.Versioning.ApiExplorer;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace API
{
    public class ConfigureSwaggerOptions: IConfigureOptions<SwaggerGenOptions>
    {
        private readonly IApiVersionDescriptionProvider _provider;

        public ConfigureSwaggerOptions(IApiVersionDescriptionProvider provider)
        {
            _provider = provider;
        }


        public void Configure(SwaggerGenOptions options)
        {
            // Generate the swagger doc for each version of the API
            foreach (var description in _provider.ApiVersionDescriptions)
            {
                options.SwaggerDoc(description.GroupName, CreateVersionInfo(description));
            }
        }


        private OpenApiInfo CreateVersionInfo(ApiVersionDescription desc) {

            var info = new OpenApiInfo()
            {
                // The title in the swagger dropdown box and version number.
                Title = "API",
                Version = desc.ApiVersion.ToString()
            };

            if (desc.IsDeprecated)
            {
                // Deprication warning if API is highlighted as depricated.
                info.Description += " (Depricated) This API version has been deprecated.";
            }

            return info;
        }
    }
}
