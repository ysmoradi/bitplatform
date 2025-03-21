﻿//+:cnd:noEmit
using Fido2NetLib;
using Fido2NetLib.Objects;
//#if (sample == true)
using Boilerplate.Shared.Dtos.Todo;
//#endif
//#if (module == "Admin")
using Boilerplate.Shared.Dtos.Dashboard;
//#endif
//#if (module == "Admin" || module == "Sales")
using Boilerplate.Shared.Dtos.Products;
using Boilerplate.Shared.Dtos.Categories;
//#endif
//#if (notification == true)
using Boilerplate.Shared.Dtos.PushNotification;
//#endif
using Boilerplate.Shared.Dtos.Identity;
using Boilerplate.Shared.Dtos.Statistics;

namespace Boilerplate.Shared.Dtos;

/// <summary>
/// https://devblogs.microsoft.com/dotnet/try-the-new-system-text-json-source-generator/
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
[JsonSerializable(typeof(Dictionary<string, string?>))]
[JsonSerializable(typeof(TimeSpan))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(Guid[]))]
[JsonSerializable(typeof(GitHubStats))]
[JsonSerializable(typeof(NugetStatsDto))]
[JsonSerializable(typeof(AppProblemDetails))]
//#if (notification == true)
[JsonSerializable(typeof(PushNotificationSubscriptionDto))]
//#endif
//#if (sample == true)
[JsonSerializable(typeof(TodoItemDto))]
[JsonSerializable(typeof(PagedResult<TodoItemDto>))]
[JsonSerializable(typeof(List<TodoItemDto>))]
//#endif
//#if (module == "Admin" || module == "Sales")
[JsonSerializable(typeof(CategoryDto))]
[JsonSerializable(typeof(List<CategoryDto>))]
[JsonSerializable(typeof(PagedResult<CategoryDto>))]
[JsonSerializable(typeof(ProductDto))]
[JsonSerializable(typeof(List<ProductDto>))]
[JsonSerializable(typeof(PagedResult<ProductDto>))]
//#endif
//#if (module == "Admin")
[JsonSerializable(typeof(List<ProductsCountPerCategoryResponseDto>))]
[JsonSerializable(typeof(OverallAnalyticsStatsDataResponseDto))]
[JsonSerializable(typeof(List<ProductPercentagePerCategoryResponseDto>))]
//#endif
[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(AuthenticatorAttestationRawResponse))]
[JsonSerializable(typeof(CredentialCreateOptions))]
[JsonSerializable(typeof(VerifyAssertionResult))]
[JsonSerializable(typeof(VerifyWebAuthnAndSignInDto))]
[JsonSerializable(typeof(WebAuthnAssertionOptionsRequestDto))]
public partial class AppJsonContext : JsonSerializerContext
{
}
