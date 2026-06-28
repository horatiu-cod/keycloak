namespace Keycloak.Authentication.Common;

internal static class NormalizeUrl
{
    public static string NormalizeStartUrl(string url) => url.StartsWith('/') ? url.TrimStart('/') : url;
    public static string NormalizeEndUrl(string url) => url.EndsWith('/') ? url.TrimEnd('/') : url;
}
