using Keycloak.Authentication.Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Keycloak.Authentication;

public static class LoginLogoutEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapLoginAndLogoutEndPoints(this IEndpointRouteBuilder endpoints, string loginRedirectUri, string logoutRedirectUri, string? openIdConnectDefaultsScheme = null, string? cookieAuthenticationDefaultsScheme = null)
    {
        var schemes = new List<string>();
        cookieAuthenticationDefaultsScheme ??= CookieAuthenticationDefaults.AuthenticationScheme;
        openIdConnectDefaultsScheme ??= OpenIdConnectDefaults.AuthenticationScheme;
        schemes.Add(cookieAuthenticationDefaultsScheme);
        schemes.Add(openIdConnectDefaultsScheme);

        var group = endpoints.MapGroup("authentication");

        group.MapGet("/login", () => TypedResults.Challenge(new AuthenticationProperties { RedirectUri = $"/{NormalizeUrl.NormalizeStartUrl(loginRedirectUri)}"}, schemes))
            .AllowAnonymous();

        group.MapPost("/logout", () => TypedResults.SignOut(new AuthenticationProperties { RedirectUri = $"/{NormalizeUrl.NormalizeStartUrl(logoutRedirectUri)}" },
            schemes));

        return group;
    }
}
