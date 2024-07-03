using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace OAuth.AuthorizationServer
{
    public class AuthService
    {
        public static List<string> GetDestinations(Claim claim)
        {
            var destinations = new List<string>();

            if (claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
            {
                destinations.Add(OpenIddictConstants.Destinations.AccessToken);
            }
            return destinations;
        }
        public string BuilderRedirectUrl(HttpRequest request, IDictionary<string, StringValues> parameters)
        {
            var url = request.PathBase + request.Path + QueryString.Create(parameters);

            return url;
        }        
        public IDictionary<string, StringValues> ParseOAuthParameters(HttpContext httpContext, List<string>? excluding = null)
        {
            var parameters = httpContext.Request.HasFormContentType
                ? httpContext.Request.Form
                    .Where(parameter => !excluding.Contains(parameter.Key))
                    .ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
                : httpContext.Request.Query
                    .Where(parameter => !excluding.Contains(parameter.Key))
                    .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            return parameters;
        }
        public bool IsAuthenticated(AuthenticateResult authenticateResult, OpenIddictRequest request)
        {
            if (!authenticateResult.Succeeded)
            {
                return false;
            }

            if (request.MaxAge.HasValue && authenticateResult.Properties != null)
            {
                var maxAgeSecond = TimeSpan.FromSeconds(request.MaxAge.Value);
                var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                    DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeSecond;

                if (expired)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
