using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Web;
using System.Net;
using System.Collections.Immutable;
using static System.Runtime.InteropServices.JavaScript.JSType;
using OAuth.AuthorizationServer;
using Microsoft.AspNetCore.Authorization;

namespace OAuthAPI.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthService _authService;

        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            AuthService authService)
        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _authService = authService;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var parameters = _authService.ParseOAuthParameters(HttpContext, new List<string> { Parameters.Prompt });

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);


            // Try to retrieve the user principal stored in the authentication cookie and redirect
            // the user agent to the login page (or to an external provider) in the following cases:
            //
            //  - If the user principal can't be extracted or the cookie is too old.
            //  - If prompt=login was specified by the client application.
            //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
            //
            // For scenarios where the default authentication handler configured in the ASP.NET Core
            // authentication options shouldn't be used, a specific scheme can be specified here.

            if (!_authService.IsAuthenticated(result, request))
            {
                return Challenge(properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
            }

            // Retrieve the application details from the database.
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                         throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var consentType = await _applicationManager.GetConsentTypeAsync(application);


            if (consentType != ConsentTypes.Explicit)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Only explicit consent clients are supported"
                    }));
            }

            var consentClaim = result.Principal.GetClaim(Consts.ConsentNaming);

            // it might be extended in a way that consent claim will contain list of allowed client ids.
            if (consentClaim != Consts.GrantAccessValue)
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
                var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
            }


            var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Add the claims that will be persisted in the tokens.
            identity.SetClaim(Claims.Subject, userId)
                    .SetClaim(Claims.Email, userId)
                    .SetClaim(Claims.Name, userId)
                    .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(c => AuthService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.            
        //var authorizations = await _authorizationManager
        //        .FindAsync(
        //        subject: userId,
        //        client: await _applicationManager.GetIdAsync(application),
        //        status: Statuses.Valid,
        //        type: AuthorizationTypes.Permanent,
        //        scopes: identity.GetScopes())
        //        .ToListAsync();

        //    var authorization = authorizations.LastOrDefault();

        //    authorization ??= await _authorizationManager.CreateAsync(
        //        identity: identity,
        //        subject: userId,
        //        client: await _applicationManager.GetIdAsync(application),
        //        type: AuthorizationTypes.Permanent,
        //        scopes: identity.GetScopes());

        //    identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        //    identity.SetDestinations(AuthService.GetDestinations);

        //    return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        //}

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                  throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");

            // Retrieve the claims principal stored in the authorization code/refresh token.
            var result =
                    await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);

            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                   authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                   properties: new AuthenticationProperties(new Dictionary<string, string>
                   {
                       [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                       [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Cannot find user from the token."
                   }));
            }


            var identity = new ClaimsIdentity(result.Principal.Claims,
         authenticationType: TokenValidationParameters.DefaultAuthenticationType,
         nameType: Claims.Name,
         roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                  .SetClaim(Claims.Email, userId)
                  .SetClaim(Claims.Name, userId)
                  .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetDestinations(c => AuthService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                  authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                  properties: new AuthenticationProperties
                  {
                      RedirectUri = "/"
                  });
        }
    }
}
