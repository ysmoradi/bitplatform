﻿//+:cnd:noEmit
namespace Boilerplate.Shared;

public static partial class Urls
{
    public const string HomePage = "/";

    public const string NotFoundPage = "/not-found";

    public const string TermsPage = "/terms";

    public const string SettingsPage = "/settings";

    public const string AboutPage = "/about";

    //#if (module == "Admin")

    public const string CategoriesPage = "/categories";

    public const string DashboardPage = "/dashboard";

    public const string ProductsPage = "/products";

    public const string AddOrEditProductPage = "/add-edit-product";

    //#endif
    //#if (sample == true)
    public const string TodoPage = "/todo";
    //#endif
    //#if (module == "Sales")
    public const string ProductPage = "/product";
    //#endif

    //#if (signalR == true)
    public const string SystemPrompts = "/system-prompts";
    //#endif

    public const string Authorize = "/authorize";

    public const string RolesPage = "/user-groups";

    public const string UsersPage = "/users";

    //#if (offlineDb == true)
    public const string OfflineDatabaseDemo = "/offline-database-demo";
    //#endif
}
