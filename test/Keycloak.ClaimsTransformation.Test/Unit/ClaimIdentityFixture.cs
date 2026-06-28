using System.Security.Claims;

namespace Keycloak.ClaimsTransformation.Test.Unit;

public class ClaimIdentityFixture
{
    // The issuer/original issuer
    public string MyServerUrl = "https://keycloak.mydomain.com/realms/realm";

    // The value type should be JSON
    private const string MyValueType = "JSON";

    // The audience for the resource_access
    public const string MyAudience = "audience";

    //public ClaimIdentityFixture()
    //{
    //    SetClaimsIdentity = new ClaimsPrincipal(new ClaimsIdentity(
    //    [
    //    new Claim(ClientResourceClaimType, ClientResourceClaimValue, MyValueType, MyServerUrl, MyServerUrl),
    //    new Claim(RealmClaimType, RealmClaimValue, MyValueType, MyServerUrl, MyServerUrl),
    //    new Claim("preferred_username", "horatiu"),
    //    new Claim(ClaimTypes.Name, "horatiu cod"),
    //    new Claim(ClaimTypes.Email, "horatiu@52.ro"),
    //    new Claim("iss", MyServerUrl)
    //    ],"Basic"));
    //}
    public ClaimsPrincipal SetClaimsIdentityAuthenticated => new ClaimsPrincipal(new ClaimsIdentity(
        [
        new Claim(ClientResourceClaimType, ClientResourceClaimValue, MyValueType, MyServerUrl, MyServerUrl),
        new Claim(RealmClaimType, RealmClaimValue, MyValueType, MyServerUrl, MyServerUrl),
        new Claim("preferred_username", "horatiu"),
        new Claim(ClaimTypes.Name, "horatiu cod"),
        new Claim(ClaimTypes.Email, "horatiu@52.ro"),
        new Claim("iss", MyServerUrl)
        ], "Basic"));

    public ClaimsPrincipal SetClaimsIdentityNotAuthenticated => new ClaimsPrincipal(new ClaimsIdentity(
    [
    new Claim(ClientResourceClaimType, ClientResourceClaimValue, MyValueType, MyServerUrl, MyServerUrl),
        new Claim(RealmClaimType, RealmClaimValue, MyValueType, MyServerUrl, MyServerUrl),
        new Claim("preferred_username", "horatiu"),
        new Claim(ClaimTypes.Email, "horatiu@52.ro"),
        new Claim("iss", MyServerUrl)
    ]));

    // The resource_access claim type
    private const string ClientResourceClaimType = "resource_access";
    private const string ClientResourceClaimValue = @$"{{""{MyAudience}"":{{""roles"":[""{FirstClientClaim}"",""{SecondClientClaim}""]}}}}";

    // The realm_access claim type
    private const string RealmClaimType = "realm_access";
    private const string RealmClaimValue = @$"{{""roles"":[""{FirstRealmClaim}"",""{SecondRealmClaim}""]}}";

    // Fake claim values
    public const string FirstClientClaim = "client_first_role";
    private const string SecondClientClaim = "client_second_role";
    private const string FirstRealmClaim = "realm_first_role";
    private const string SecondRealmClaim = "realm_second_role";

}
