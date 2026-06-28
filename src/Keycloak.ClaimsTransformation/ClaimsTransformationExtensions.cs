using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Keycloak.ClaimsTransformation;

public static class ClaimsTransformationExtensions
{
    public static void AddKeycloakJwtClaimsTransformation(this IServiceCollection services , string issuer, string audience)
    {
        //services.AddTransient<KeycloakClaimsTransformation>();
        services.AddTransient<IClaimsTransformation>(sp =>new  KeycloakClaimsTransformation(issuer, audience));
    }
}
