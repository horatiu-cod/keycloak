using Keycloak.Authentication.Configuration;
using Keycloak.ClaimsTransformation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Keycloak.Authentication;

public static class AuthenticationBuilderExtensions
{
    private const string KeycloakBackchannel = nameof(KeycloakBackchannel);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to</param>
    /// <param name="configSectionPath">The name of the appsettings.json section used to resolve the Keycloak server URL and Audience. </param>
    /// <remarks>
    /// The <paramref name="configSectionPath"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL and audience is the client.If is not provided will use the default "Keycloak" section.
    /// For example, if <paramref name="configSectionPath"/> is 
    /// "Keycloak:{
    ///     ServerUri = localhost:port,
    ///     Realm = myrealm,
    ///     Client = myclient,
    /// }"
    /// the authority URL will be "https+http://keycloak/realms/myrealm" and audience will be "myclient".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakJwtBearer(this AuthenticationBuilder builder, string? configSectionPath = null)
    {
        var serverUri = string.Empty;
        var realm = string.Empty;
        var client = string.Empty;
        configSectionPath = string.IsNullOrEmpty(configSectionPath) ? "Keycloak" : configSectionPath ;
        IdentityModelEventSource.ShowPII = true;
        string message = "Fail validation";
        builder.Services.AddOptionsWithValidateOnStart<KeycloakOptions>()
            .BindConfiguration(configSectionPath).Validate(keycloakOptions =>
            {
                serverUri = keycloakOptions.ServerUrl;
                realm = keycloakOptions.Realm;
                client = keycloakOptions.Client;

                return ValidateOptions(keycloakOptions, serverUri, realm, ref message);
            }, message);
            return builder.AddKeycloakJwtBearer(serverUri, realm, client);
    }
    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakJwtBearer(this AuthenticationBuilder builder, string serverUri, string realm, string client) => builder.AddKeycloakJwtBearer(serverUri, realm, client,JwtBearerDefaults.AuthenticationScheme, null);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="authenticationScheme">The authentication scheme name. Default is "Bearer".</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakJwtBearer(this AuthenticationBuilder builder, string serverUri, string realm, string client, string authenticationScheme) => builder.AddKeycloakJwtBearer(serverUri, realm, client, authenticationScheme, null);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="configureOptions">An action to configure the <see cref="JwtBearerOptions"/>.</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakJwtBearer(this AuthenticationBuilder builder, string serverUri, string realm, string client, Action<JwtBearerOptions> configureOptions) => builder.AddKeycloakJwtBearer(serverUri, realm, client, JwtBearerDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="authenticationScheme">The authentication scheme name. Default is "Bearer".</param>
    /// <param name="configureOptions">An action to configure the <see cref="JwtBearerOptions"/>.</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakJwtBearer(this AuthenticationBuilder builder, string serverUri, string realm, string client, string authenticationScheme, Action<JwtBearerOptions>? configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var issuer = GetAuthorityUri(serverUri, realm) ?? string.Empty;

        builder.AddJwtBearer(authenticationScheme);

        builder.Services.AddHttpClient(KeycloakBackchannel);
        builder.Services.AddKeycloakJwtClaimsTransformation(issuer, client);

        builder.Services
               .AddOptions<JwtBearerOptions>(authenticationScheme)
               .Configure<IConfiguration, IHttpClientFactory, IHostEnvironment>((options, configuration, httpClientFactory, hostEnvironment) =>
               {
                   options.Backchannel = httpClientFactory.CreateClient(KeycloakBackchannel);
                   options.Authority = issuer;
                   options.Audience = client;

                   configureOptions?.Invoke(options);
               });
        return builder;
    }
    /// <summary>
    /// Adds Keycloak OpenID Connect authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to</param>
    /// <param name="configSectionPath">The name of the appsettings.json section used to resolve the Keycloak server URL and Audience. </param>
    /// <remarks>
    /// The <paramref name="configSectionPath"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL and audience is the client.If is not provided will use the default "Keycloak" section.
    /// For example, if <paramref name="configSectionPath"/> is 
    /// "keycloak:{
    ///     ServerUri = localhost:port,
    ///     Realm = myrealm,
    ///     Client = myclient,
    ///     ClientSecret = mysecret,
    /// }"
    /// the authority URL will be "https+http://keycloak/realms/myrealm" and audience will be "myclient".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string? configSectionPath = null)
    {
        var serverUri = string.Empty;
        var realm = string.Empty;
        var client = string.Empty;
        var clientSecret = string.Empty;
        configSectionPath ??= "Keycloak";
        IdentityModelEventSource.ShowPII = true;
        string message = string.Empty;
        builder.Services.AddOptionsWithValidateOnStart<KeycloakOptions>()
            .BindConfiguration(configSectionPath).Validate(keycloakOptions =>
            {
                serverUri = keycloakOptions.ServerUrl;
                realm = keycloakOptions.Realm;
                client = keycloakOptions.Client;
                clientSecret = keycloakOptions.ClientSecret;
                return ValidateOptions(keycloakOptions, serverUri, realm, ref message);
            }, message);
        return builder.AddKeycloakOpenIdConnect(serverUri, realm, client, clientSecret);
    }

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The public client of the Keycloak server for which is requested the authentication</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string serverUri, string realm, string client) => builder.AddKeycloakOpenIdConnect(serverUri, realm, client, string.Empty, OpenIdConnectDefaults.AuthenticationScheme, null);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="clientSecret">The secret of the client of the Keycloak server for which is requested the authentication </param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string serverUri, string realm, string client, string clientSecret ) => builder.AddKeycloakOpenIdConnect(serverUri, realm, client, clientSecret, OpenIdConnectDefaults.AuthenticationScheme, null);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// 
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string serverUri, string realm, string client, Action<OpenIdConnectOptions> configureOptions) => builder.AddKeycloakOpenIdConnect(serverUri, realm, client, string.Empty, OpenIdConnectDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="clientSecret">The secret of the client of the Keycloak server for which is requested the authentication </param>
    /// <param name="authenticationScheme">The OpenID Connect authentication scheme name. Default is "OpenIdConnect".</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string serverUri, string realm, string client, string clientSecret, string authenticationScheme) => builder.AddKeycloakOpenIdConnect(serverUri, realm, client, clientSecret, authenticationScheme, null);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="clientSecret">The secret of the client of the Keycloak server for which is requested the authentication </param>
    /// <param name="configureOptions">An action to configure the <see cref="OpenIdConnectOptions"/>.</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// The <paramref name="client"/> is used to resolve the audience.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string serverUri, string realm, string client, string clientSecret, Action<OpenIdConnectOptions> configureOptions) => builder.AddKeycloakOpenIdConnect(serverUri, realm, client, clientSecret, OpenIdConnectDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds Keycloak JWT Bearer authentication to the application.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" /> to add services to.</param>
    /// <param name="serverUri">The name of the service used to resolve the Keycloak server URL.</param>
    /// <param name="realm">The realm of the Keycloak server to connect to.</param>
    /// <param name="client">The client of the Keycloak server for which is requested the authentication</param>
    /// <param name="clientSecret">The secret of the client of the Keycloak server for which is requested the authentication </param>
    /// <param name="authenticationScheme">The OpenID Connect authentication scheme name. Default is "OpenIdConnect".</param>
    /// <param name="configureOptions">An action to configure the <see cref="OpenIdConnectOptions"/>.</param>
    /// <remarks>
    /// The <paramref name="serverUri"/> is used to resolve the Keycloak server URL and is combined with the realm to form the authority URL.
    /// For example, if <paramref name="serverUri"/> is "keycloak:port" and <paramref name="realm"/> is "myrealm", the authority URL will be "https+http://keycloak:port/realms/myrealm".
    /// </remarks>
    public static AuthenticationBuilder AddKeycloakOpenIdConnect(this AuthenticationBuilder builder, string serverUri, string realm, string client, string clientSecret, string authenticationScheme, Action<OpenIdConnectOptions>? configureOptions) 
    {
        ArgumentNullException.ThrowIfNull(builder);

        var issuer = GetAuthorityUri(serverUri, realm) ?? string.Empty;

        builder.AddOpenIdConnect(authenticationScheme, options => { });

        builder.Services.AddHttpClient(KeycloakBackchannel);
        builder.Services.AddKeycloakJwtClaimsTransformation(issuer, client);


        builder.Services.AddOptions<OpenIdConnectOptions>(authenticationScheme)
            .Configure<IConfiguration, IHttpClientFactory, IHostEnvironment>((options, configuration, httpClientFactory, hostEnvironment) =>
            {
                options.SignOutScheme = authenticationScheme;
                options.Backchannel = httpClientFactory.CreateClient(KeycloakBackchannel);
                options.Authority = issuer;

                options.ClientId = client;
                options.ClientSecret = clientSecret;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.SaveTokens = true;
                options.MapInboundClaims = false;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("roles");
                options.UseTokenLifetime = true;
                options.ClaimActions.MapAll();
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters.ValidAudience = client;
                options.TokenValidationParameters.ValidIssuer = GetAuthorityUri(serverUri, realm);

                configureOptions?.Invoke(options);
            });
        return builder;
    }

    private static bool ValidateOptions(KeycloakOptions keycloakOptions, string serverUri, string realm, ref string message)
    {
        if (string.IsNullOrEmpty(keycloakOptions.ServerUrl) && !Uri.IsWellFormedUriString(GetAuthorityUri(serverUri, realm), UriKind.RelativeOrAbsolute))
        {
            message = "Server URL is not valid";
            return false;
        }
        if (string.IsNullOrEmpty(keycloakOptions.Realm))
        {
            message = "Realm name missing";
            return false;
        }
        if (string.IsNullOrEmpty(keycloakOptions.Client))
        {
            message = "Client ID missing";
            return false;
        }
        return true;
    }

    private static string? GetAuthorityUri(string serverUri, string realm) =>  $"https://{serverUri}/realms/{realm}";
}
