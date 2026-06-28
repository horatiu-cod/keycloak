using System.Security.Claims;

namespace Keycloak.ClaimsTransformation.Extensions;

internal static class ClaimsIdentityExtension
{
    /// <summary>
    /// System.Security.Claims.ClaimsIdentity extension method
    /// </summary>
    /// <param name="claimsIdentity"></param>
    /// <param name="claim"></param>
    /// <param name="returnClaim"></param>
    /// <returns>
    /// True if passed claim found. Return the found claim
    /// </returns>
    public static bool TryGetClaim(this ClaimsIdentity claimsIdentity, Predicate<Claim> claim, out Claim? returnClaim)
    {
        if (claimsIdentity.HasClaim(claim))
        {
            returnClaim = claimsIdentity.FindFirst(claim);
            return true;
        }
        returnClaim = null;
        return false;
    }

}
