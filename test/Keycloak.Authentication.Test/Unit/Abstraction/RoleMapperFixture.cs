using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace Keycloak.Authentication.Test.Unit.Abstraction;

public class RoleMapperFixture
{
    public UserInformationReceivedContext Fake(string authType)
    {
        var openIdConnectOptions = new OpenIdConnectOptions()
        {
            ClientId = "frontend"
        };
        var authenticationScheme = new AuthenticationScheme("", "", typeof(FakeAuthenticationHandler));
        var principal = Principal(authType);
        var httpContext = new DefaultHttpContext();
        var Context = new UserInformationReceivedContext(httpContext, authenticationScheme, openIdConnectOptions, principal, null);
        return Context;
    }

    public static ClaimsPrincipal Principal (string authType) => new ClaimsPrincipal(new ClaimsIdentity(null, authType));
}
public class FakeAuthenticationOptions : AuthenticationSchemeOptions
{
    public FakeAuthenticationOptions()
    {

    }
}

public class FakeAuthenticationHandler : AuthenticationHandler<FakeAuthenticationOptions>
{
    public FakeAuthenticationHandler(IOptionsMonitor<FakeAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        throw new NotImplementedException();
    }
}

