using System.Text.RegularExpressions;
using Boilerplate.Shared.Controllers.Identity;

namespace Boilerplate.Client.Core.Components.Pages;

// Opening https://boilerplate-based-project.com/authorize?client_id=NopCommerceClient1&redirect_uri=https://my-nop-commerce-website.com/login&State=carts
// Will open https://my-nop-commerce-website.com/login#access_token=di1d98cxh913fh29ufhnfunxw9&expires_in=3600&state=carts
// Local test url: http://localhost:5030/authorize?client_id=NopClient&redirect_uri=https://my-nop-commerce-website.com/login&state=carts

public partial class Authorize
{
    [AutoInject] private IUserController userController = default!;
    [AutoInject] private IAuthTokenProvider authTokenProvider = default!;

    [Parameter, SupplyParameterFromQuery(Name = "client_id")] public string? ClientId { get; set; }
    [Parameter, SupplyParameterFromQuery(Name = "redirect_uri")] public string? RedirectUri { get; set; }
    [Parameter, SupplyParameterFromQuery(Name = "state")] public string? State { get; set; }

    private Dictionary<string, string[]> clients = new() // You can also fetch clients from server api
    {
        {
            "NopClient",
            [
                "https://my-nop-commerce-website.com/login",
                "https://localhost:5030/BitAuth/LoginCallback",
                "https://demo-sso.azurewebsites.net/BitAuth/LoginCallback",
                "https://nopclient.azurewebsites.net/BitAuth/LoginCallback",
            ]
        },
    };

    protected override async Task OnAfterFirstRenderAsync()
    {
        if (clients.TryGetValue(ClientId!, out var clientAllowedRedirectUrls) is false)
        {
            NavigationManager.NavigateTo($"{RedirectUri}#error=Invalid or missing client_id&state={State}");
            return;
        }
        Uri uri = new Uri(RedirectUri!);
        string cleanReturnUrl = uri.GetLeftPart(UriPartial.Path);
        string normalizedUrl = Regex.Replace(cleanReturnUrl, "(?<!:)/{2,}", "/");
        if (clientAllowedRedirectUrls.Any(clientUrl => string.Equals(clientUrl, normalizedUrl, StringComparison.InvariantCultureIgnoreCase)) is false)
        {
            NavigationManager.NavigateTo($"{RedirectUri}#error=Invalid redirect uri&state={State}");
            return;
        }

        _ = await userController.GetCurrentUser(CurrentCancellationToken); // Make sure the current user session still valid.

        var accessToken = await authTokenProvider.GetAccessToken();

        var token = IAuthTokenProvider.ParseAccessToken(accessToken, validateExpiry: true);

        var expiresIn = long.Parse(token.FindFirst("exp")!.Value) - long.Parse(token.FindFirst("iat")!.Value);

        NavigationManager.NavigateTo($"{normalizedUrl}?access_token={accessToken}&token_type=Bearer&expires_in={expiresIn}&state={State}");

        await base.OnAfterFirstRenderAsync();
    }
}
