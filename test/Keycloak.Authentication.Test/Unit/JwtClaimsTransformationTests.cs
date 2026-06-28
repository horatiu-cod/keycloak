using FluentAssertions;
using Keycloak.Authentication.Test.Unit.Abstraction;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace Keycloak.Authentication.Test.Unit;

public class JwtClaimsTransformationTests : IClassFixture<ClaimIdentityFixture>
{
    private readonly ClaimIdentityFixture _claimIdentityFixture;
    private readonly string _serverUrl;

    public JwtClaimsTransformationTests(ClaimIdentityFixture claimIdentityFixture)
    {
        _claimIdentityFixture = claimIdentityFixture;
        _serverUrl = claimIdentityFixture.MyServerUrl;
    }

    [Fact]
    public async Task TransformAsync_WhenIsAuthenticated_ShouldReturnJwtIdentityType()
    {

        IOptions<JwtBearerOptions> JwtOptions = Options.Create(new JwtBearerOptions
        {
            Authority = _serverUrl,
            Audience = "audience",
        });
        var transformation = new JwtClaimsTransformation(JwtOptions);
        //Act
        var claimsPrincipal = _claimIdentityFixture.SetClaimsIdentityAuthenticated;

        await transformation.TransformAsync(claimsPrincipal);
        var claimsIdentity = (ClaimsIdentity?)claimsPrincipal.Identity;
        //Assert
        claimsIdentity.Should().NotBeNull();
        claimsIdentity!.TryGetClaim(c => c.Type == ClaimTypes.Name, out var claim).Should().BeTrue();
        claim?.Value.Should().Be("horatiu");
        claimsIdentity!.HasClaim(ClaimTypes.Role, "client_first_role").Should().BeTrue();
        claimsIdentity.HasClaim(ClaimTypes.Role, "client_second_role").Should().BeTrue();
        claimsIdentity.HasClaim(ClaimTypes.Role, "realm_first_role").Should().BeTrue();
        claimsIdentity.HasClaim(ClaimTypes.Role, "realm_second_role").Should().BeTrue();
        claimsIdentity.Claims.Count(item => ClaimTypes.Role == item.Type).Should().Be(4);
    }

    [Fact]
    public async Task TransformAsync_WhenIsNotAuthenticated_ShouldNotReturnJwtIdentityType()
    {

        IOptions<JwtBearerOptions> JwtOptions = Options.Create(new JwtBearerOptions
        {
            Authority = _serverUrl,
            Audience = "audience",
        });
        var transformation = new JwtClaimsTransformation(JwtOptions);
        //Act
        var claimsPrincipal = _claimIdentityFixture.SetClaimsIdentityNotAuthenticated;

        await transformation.TransformAsync(claimsPrincipal);
        var claimsIdentity = (ClaimsIdentity?)claimsPrincipal.Identity;
        //Assert
        claimsIdentity.Should().NotBeNull();
        claimsIdentity!.TryGetClaim(c => c.Type == ClaimTypes.Name, out var claim).Should().BeFalse();
        claimsIdentity!.HasClaim(ClaimTypes.Role, "client_first_role").Should().BeFalse();
        claimsIdentity.HasClaim(ClaimTypes.Role, "client_second_role").Should().BeFalse();
        claimsIdentity.HasClaim(ClaimTypes.Role, "realm_first_role").Should().BeFalse();
        claimsIdentity.HasClaim(ClaimTypes.Role, "realm_second_role").Should().BeFalse();
        claimsIdentity.Claims.Count(item => ClaimTypes.Role == item.Type).Should().Be(0);
    }
}
