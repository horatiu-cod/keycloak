using BlazorServerApp.Components;
using Keycloak.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
    .AddKeycloakOpenIdConnect("localhost:8443", "oidc", "frontend", "", "OpenIdConnectDefaults.AuthenticationScheme")
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => options.Cookie.IsEssential = true);

builder.Services.AddAuthorizationBuilder();
builder.Services.AddCascadingAuthenticationState();


var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode();

app.MapLoginAndLogoutEndPoints("", "", "OpenIdConnectDefaults.AuthenticationScheme",  CookieAuthenticationDefaults.AuthenticationScheme);

app.Run();
