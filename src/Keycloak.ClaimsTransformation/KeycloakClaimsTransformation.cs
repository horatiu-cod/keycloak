using Keycloak.ClaimsTransformation.Common;
using Keycloak.ClaimsTransformation.Extensions;
using Keycloak.ClaimsTransformation.Mappers;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Keycloak.ClaimsTransformation;

internal class KeycloakClaimsTransformation(string issuer, string audience): IClaimsTransformation
{
    private readonly string _issuer = issuer;
    private readonly string _audience = audience;

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var claimsIdentity = (ClaimsIdentity?)principal.Identity;
        if (claimsIdentity is not null && ShouldTransform(claimsIdentity))
        {
            MapRoleClaim(claimsIdentity);
            MapNameClaim(claimsIdentity);
        }
        return Task.FromResult(principal);
    }
    private bool ShouldTransform(ClaimsIdentity? claimsIdentity)
    {
        if (claimsIdentity is not null && claimsIdentity.HasClaim(c => c.Type == Constants.RoleClaimType))
        {
            return false;
        }
        if (claimsIdentity is not null && claimsIdentity.IsAuthenticated && claimsIdentity.TryGetClaim(c => c.Type == Constants.IssuerClaimType, out var issClaim) && issClaim is not null)
        {
            return string.Equals(issClaim.Value, _issuer, StringComparison.InvariantCultureIgnoreCase);
        }
        return false;
    }
    /// <summary>
    /// Map and transform the keycloak jwt "roles" claim to identity "role" claim type
    /// </summary>
    /// <param name="claimsIdentity"></param>
    private void MapRoleClaim(ClaimsIdentity? claimsIdentity)
    {
        if (claimsIdentity is not null)
        {
            var roles = RoleClaimsMapper.GetRoles(claimsIdentity, _audience);
            foreach (var role in roles)
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
            }

        }
    }
    /// <summary>
    /// Map and transform the keycloak jwt "preferred_username" claim to identity "name" claim type
    /// </summary>
    /// <param name="claimsIdentity">The current identity</param>
    private static void MapNameClaim(ClaimsIdentity? claimsIdentity)
    {
        if (claimsIdentity is not null && claimsIdentity.TryGetClaim(c => c.Type == Constants.NameClaimType, out var claimToSet))
        {
            var nameClaim = claimsIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            claimsIdentity.TryRemoveClaim(nameClaim);
            if (claimToSet is not null)
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, claimToSet.Value));
            return;
        }
        return;
    }
}
