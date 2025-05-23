﻿//+:cnd:noEmit
using Boilerplate.Shared.Dtos.Identity;
using Boilerplate.Shared.Controllers.Identity;
using Microsoft.AspNetCore.Components.Routing;

namespace Boilerplate.Client.Core.Components.Pages.Identity.SignIn;

public partial class SignInPage
{

    [Parameter, SupplyParameterFromQuery(Name = "return-url")]
    public string? ReturnUrlQueryString { get; set; }

    [Parameter, SupplyParameterFromQuery(Name = "userName")]
    public string? UserNameQueryString { get; set; }

    [Parameter, SupplyParameterFromQuery(Name = "email")]
    public string? EmailQueryString { get; set; }

    [Parameter, SupplyParameterFromQuery(Name = "phoneNumber")]
    public string? PhoneNumberQueryString { get; set; }

    [Parameter, SupplyParameterFromQuery(Name = "otp")]
    public string? OtpQueryString { get; set; }

    [Parameter, SupplyParameterFromQuery(Name = "error")]
    public string? ErrorQueryString { get; set; }


    [AutoInject] private IWebAuthnService webAuthnService = default!;

    [AutoInject] private ILocalHttpServer localHttpServer = default!;
    [AutoInject] private ITelemetryContext telemetryContext = default!;
    [AutoInject] private IIdentityController identityController = default!;
    [AutoInject] private IExternalNavigationService externalNavigationService = default!;


    private bool isWaiting;
    private bool isOtpSent;
    private bool sucssefulSignIn;
    private bool requiresTwoFactor;
    private JsonElement? webAuthnAssertion;
    private SignInPanelTab currentSignInPanelTab;
    private readonly SignInRequestDto model = new();
    private AppDataAnnotationsValidator? validatorRef;

    protected override async Task OnInitAsync()
    {
        await base.OnInitAsync();

        model.UserName = UserNameQueryString;
        model.Email = EmailQueryString;
        model.PhoneNumber = PhoneNumberQueryString;

        if (string.IsNullOrEmpty(OtpQueryString) is false)
        {
            model.Otp = OtpQueryString;

            if (InPrerenderSession is false &&
                (string.IsNullOrEmpty(model.UserName) is false ||
                 string.IsNullOrEmpty(model.Email) is false ||
                 string.IsNullOrEmpty(model.PhoneNumber) is false))
            {
                await DoSignIn();
            }
        }

        if (string.IsNullOrEmpty(ErrorQueryString) is false)
        {
            SnackBarService.Error(ErrorQueryString);
        }
    }

    private async Task ShowSignInPanel(LocationChangingContext args)
    {
        // We're treating OtpPanel and TfaPanel as modal dialogs. This means that no matter where the user tries to navigate,
        // we will block the navigation and close either the TfaPanel or OtpPanel if it's visible.
        // The only exception to this is when the sign-in process is successful.
        if (sucssefulSignIn)
            return;

        args.PreventNavigation();

        webAuthnAssertion = null;

        isOtpSent = false;
        model.Otp = null;

        requiresTwoFactor = false;
        model.TwoFactorCode = null;

        await InvokeAsync(StateHasChanged);
    }

    private async Task DoSignIn()
    {
        if (isOtpSent && string.IsNullOrWhiteSpace(model.Otp)) return;

        isWaiting = true;
        sucssefulSignIn = false;

        try
        {
            if (requiresTwoFactor && string.IsNullOrWhiteSpace(model.TwoFactorCode)) return;

            if (webAuthnAssertion.HasValue)
            {
                var response = await identityController
                    .WithQueryIf(AppPlatform.IsBlazorHybrid, "origin", localHttpServer.Origin)
                    .VerifyWebAuthAndSignIn(
                        new VerifyWebAuthnAndSignInDto
                        {
                            ClientResponse = webAuthnAssertion.Value,
                            TfaCode = model.TwoFactorCode,
                            DeviceInfo = telemetryContext.Platform
                        },
                        CurrentCancellationToken);

                requiresTwoFactor = response.RequiresTwoFactor;

                if (requiresTwoFactor is false)
                {
                    sucssefulSignIn = true;
                    await AuthManager.StoreTokens(response!, model.RememberMe);
                }
            }
            else
            {
                CleanModel();

                if (validatorRef?.EditContext.Validate() is false) return;

                model.ReturnUrl = ReturnUrlQueryString;
                model.DeviceInfo = telemetryContext.Platform;

                requiresTwoFactor = await AuthManager.SignIn(model, CurrentCancellationToken);

                if (requiresTwoFactor is false)
                {
                    sucssefulSignIn = true;
                }
            }

            if (sucssefulSignIn)
            {
                NavigationManager.NavigateTo(ReturnUrlQueryString ?? Urls.HomePage, replace: true);
            }
        }
        catch (BadRequestException e) when (e.Key == nameof(AppStrings.UserIsNotConfirmed))
        {
            NavigateToConfirmPage();
        }
        catch (KnownException e)
        {
            // To disable the sign-in button until a specific time after a user lockout, use the value of `e.TryGetExtensionDataValue<TimeSpan>("TryAgainIn", out var tryAgainIn)`.
            webAuthnAssertion = null;
            SnackBarService.Error(e.Message);
        }
        finally
        {
            isWaiting = false;
        }
    }

    private async Task HandleOnSocialSignIn(string provider)
    {
        try
        {
            var port = localHttpServer.EnsureStarted();

            var redirectUrl = await identityController.GetSocialSignInUri(provider, ReturnUrlQueryString, port is -1 ? null : port, CurrentCancellationToken);

            await externalNavigationService.NavigateToAsync(redirectUrl);
        }
        catch (KnownException e)
        {
            SnackBarService.Error(e.Message);
        }
    }

    private async Task HandleOnPasswordlessSignIn()
    {
        if (isWaiting) return;
        isWaiting = true;

        try
        {
            var userIds = await webAuthnService.GetWebAuthnConfiguredUserIds();

            if (AppPlatform.IsBlazorHybrid)
            {
                localHttpServer.EnsureStarted();
            }

            var options = await identityController
                .WithQueryIf(AppPlatform.IsBlazorHybrid, "origin", localHttpServer.Origin)
                .GetWebAuthnAssertionOptions(new() { UserIds = userIds }, CurrentCancellationToken);

            try
            {
                webAuthnAssertion = await webAuthnService.GetWebAuthnCredential(options);
            }
            catch (Exception ex)
            {
                // we can safely handle the exception thrown here since it mostly because of a timeout or user cancelling the native ui.
                ExceptionHandler.Handle(ex, AppEnvironment.IsDev() ? ExceptionDisplayKind.NonInterrupting : ExceptionDisplayKind.None);
                webAuthnAssertion = null;
                return;
            }

            await DoSignIn();
        }
        catch (KnownException e)
        {
            webAuthnAssertion = null;
            SnackBarService.Error(e.Message);
        }
        finally
        {
            isWaiting = false;
        }
    }

    private void HandleOnSignInPanelTabChange(SignInPanelTab tab)
    {
        currentSignInPanelTab = tab;
    }

    private Task HandleOnSendOtp() => SendOtp(false);
    private Task HandleOnResendOtp() => SendOtp(true);
    private async Task SendOtp(bool resend)
    {
        try
        {
            CleanModel();

            if (model.Email is null && model.PhoneNumber is null) return;

            if (model.Email is not null && new EmailAddressAttribute().IsValid(model.Email) is false)
            {
                SnackBarService.Error(string.Format(AppStrings.EmailAddressAttribute_ValidationError, AppStrings.Email));
                return;
            }

            if (model.PhoneNumber is not null && new PhoneAttribute().IsValid(model.PhoneNumber) is false)
            {
                SnackBarService.Error(string.Format(AppStrings.PhoneAttribute_ValidationError, AppStrings.PhoneNumber));
                return;
            }

            var request = new IdentityRequestDto { UserName = model.UserName, Email = model.Email, PhoneNumber = model.PhoneNumber };

            await identityController.SendOtp(request, ReturnUrlQueryString, CurrentCancellationToken);

            if (resend is false)
            {
                isOtpSent = true;
            }
        }
        catch (BadRequestException e) when (e.Key == nameof(AppStrings.UserIsNotConfirmed))
        {
            NavigateToConfirmPage();
        }
        catch (KnownException e)
        {
            SnackBarService.Error(e.Message);
        }
    }

    private async Task HandleOnSendTfaToken()
    {
        try
        {
            if (webAuthnAssertion.HasValue is false)
            {
                CleanModel();

                await identityController.SendTwoFactorToken(model, CurrentCancellationToken);
            }
            else
            {
                await identityController
                    .WithQueryIf(AppPlatform.IsBlazorHybrid, "origin", localHttpServer.Origin)
                    .VerifyWebAuthAndSendTwoFactorToken(webAuthnAssertion.Value, CurrentCancellationToken);
            }

            SnackBarService.Success(Localizer[nameof(AppStrings.TfaTokenSentMessage)]);
        }
        catch (KnownException e)
        {
            SnackBarService.Error(e.Message);
        }
    }

    private void CleanModel()
    {
        if (currentSignInPanelTab is SignInPanelTab.Email)
        {
            model.PhoneNumber = null;
            if (validatorRef is null) return;

            validatorRef.EditContext.NotifyFieldChanged(validatorRef.EditContext.Field(nameof(SignInRequestDto.PhoneNumber)));
        }
        else
        {
            model.Email = null;
            if (validatorRef is null) return;

            validatorRef.EditContext.NotifyFieldChanged(validatorRef.EditContext.Field(nameof(SignInRequestDto.Email)));
        }
    }

    private void NavigateToConfirmPage()
    {
        var queryParams = new Dictionary<string, object?>
        {
            { "return-url", ReturnUrlQueryString }
        };
        if (string.IsNullOrEmpty(model.Email) is false)
        {
            queryParams.Add("email", model.Email);
        }
        if (string.IsNullOrEmpty(model.PhoneNumber) is false)
        {
            queryParams.Add("phoneNumber", model.PhoneNumber);
        }
        var confirmUrl = NavigationManager.GetUriWithQueryParameters(Urls.ConfirmPage, queryParams);
        NavigationManager.NavigateTo(confirmUrl, replace: true);
    }
}
