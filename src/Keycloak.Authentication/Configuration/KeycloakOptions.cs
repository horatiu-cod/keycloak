namespace Keycloak.Authentication.Configuration;

internal class KeycloakOptions
{
    public const string Keycloak = "Keycloak";

    public string ServerUrl { get; set; } = string.Empty;
    public string Realm { get; set; } = string.Empty;
    public string Client { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }
}
