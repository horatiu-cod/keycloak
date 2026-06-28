using FluentAssertions;
using Keycloak.Authentication.Test.Unit.Abstraction;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;

namespace Keycloak.Authentication.Test.Unit;

public class UserRoleMapperTests(RoleMapperFixture roleMapperFixture) : IClassFixture<RoleMapperFixture>
{

    [Fact]
    public void MapKeycloakRoleClaimsToIdentityRoles_WhenIsAuthenticated_ShouldMapJwtClaims()
    {
        //Arrange
        var context = roleMapperFixture.Fake("Basic");
        var jsonString = """{"sub":"0330f4a6-b572-4f1f-b052-a845118e3888","resource_access":{"backend":{"roles":["write-access","read-access"]},"frontend":{"roles":["user"]}},"email_verified":false,"realm_access":{"roles":["user-role","admin-role"]},"name":"h g","preferred_username":"h@g.com","given_name":"h","family_name":"g","email":"h@g.com"}""";
        context.User = System.Text.Json.JsonDocument.Parse(jsonString);

        //Act
        UserRoleMapper.MapKeycloakRoleClaimsToIdentityRoles(context);
        var claimsIdentity = (ClaimsIdentity?)context.Principal?.Identity;

        //Assert
        claimsIdentity.Should().NotBeNull();
        claimsIdentity!.TryGetClaim(c => c.Type == ClaimTypes.Name, out var claim).Should().BeTrue();
        claim?.Value.Should().Be("h g");
        claimsIdentity!.HasClaim(ClaimTypes.Role, "user").Should().BeTrue();
        claimsIdentity.HasClaim(ClaimTypes.Role, "user-role").Should().BeTrue();
        claimsIdentity.HasClaim(ClaimTypes.Role, "admin-role").Should().BeTrue();
        claimsIdentity.Claims.Count(item => ClaimTypes.Role == item.Type).Should().Be(3);
    }
    [Fact]
    public void MapKeycloakRoleClaimsToIdentityRoles_WhenIsNotAuthenticated_ShouldNotMapJwtClaims()
    {
        //Arrange
        var context = roleMapperFixture.Fake(string.Empty);
        var jsonString = """{"sub":"0330f4a6-b572-4f1f-b052-a845118e3888","resource_access":{"backend":{"roles":["write-access","read-access"]},"frontend":{"roles":["user"]}},"email_verified":false,"realm_access":{"roles":["user-role","admin-role"]},"name":"h g","preferred_username":"h@g.com","given_name":"h","family_name":"g","email":"h@g.com"}""";
        context.User = System.Text.Json.JsonDocument.Parse(jsonString);

        //Act
        UserRoleMapper.MapKeycloakRoleClaimsToIdentityRoles(context);
        var claimsIdentity = (ClaimsIdentity?)context.Principal?.Identity;

        //Assert
        claimsIdentity.Should().NotBeNull();
        claimsIdentity!.TryGetClaim(c => c.Type == ClaimTypes.Name, out var claim).Should().BeFalse();
        claim?.Value.Should().Be("h g");
        claimsIdentity!.HasClaim(ClaimTypes.Role, "user").Should().BeFalse();
        claimsIdentity.HasClaim(ClaimTypes.Role, "user-role").Should().BeFalse();
        claimsIdentity.HasClaim(ClaimTypes.Role, "admin-role").Should().BeFalse();
        claimsIdentity.Claims.Count(item => ClaimTypes.Role == item.Type).Should().Be(0);
    }
}
