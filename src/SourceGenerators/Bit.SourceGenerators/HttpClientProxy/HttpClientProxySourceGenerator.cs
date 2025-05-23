﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;

namespace Bit.SourceGenerators;

[Generator]
public class HttpClientProxySourceGenerator : ISourceGenerator
{
    public void Initialize(GeneratorInitializationContext context)
    {
        context.RegisterForSyntaxNotifications(() => new HttpClientProxySyntaxReceiver());
    }

    public void Execute(GeneratorExecutionContext context)
    {
        if (context.SyntaxContextReceiver is not HttpClientProxySyntaxReceiver receiver || receiver.IControllers.Any() is false)
        {
            return;
        }

        StringBuilder generatedClasses = new();

        foreach (var iController in receiver.IControllers)
        {
            StringBuilder generatedMethods = new();

            foreach (var action in iController.Actions)
            {
                string parameters = string.Join(", ", action.Parameters.Select(p => $"{p.Type.ToDisplayString()} {p.Name}"));

                var hasQueryString = action.Url.Contains('?');

                List<string> jsonReadParametersList = [];
                if (action.DoesReturnSomething && action.DoesReturnString is false)
                {
                    jsonReadParametersList.Add($"options.GetTypeInfo<{action.ReturnType.GetUnderlyingType().ToDisplayString()}>()");
                }
                if (action.HasCancellationToken)
                {
                    jsonReadParametersList.Add(action.CancellationTokenParameterName!);
                }
                var jsonReadParameters = string.Join(", ", jsonReadParametersList);

                var requestOptions = new StringBuilder();
                requestOptions.AppendLine($"__request.Options.TryAdd(\"IControllerType\", typeof({iController.Symbol.ToDisplayString(NullableFlowState.None)}));");
                requestOptions.AppendLine($"__request.Options.TryAdd(\"ActionName\", \"{action.Method.Name}\");");
                requestOptions.AppendLine($@"__request.Options.TryAdd(""ActionParametersInfo"", new Dictionary<string, Type>
                {{
                    {string.Join(", ", action.Parameters.Select(p => $"{{ \"{p.Name}\", typeof({p.Type.ToDisplayString(NullableFlowState.None)})  }}"))}
                }});");
                if (action.BodyParameter is not null)
                {
                    requestOptions.AppendLine($"__request.Options.TryAdd(\"RequestType\", typeof({action.BodyParameter.Type.ToDisplayString(NullableFlowState.None)}));");
                }
                if (action.DoesReturnSomething)
                {
                    requestOptions.AppendLine($"__request.Options.TryAdd(\"ResponseType\", typeof({action.ReturnType.GetUnderlyingType().ToDisplayString(NullableFlowState.None)}));");
                }

                var stringType = context.Compilation.GetSpecialType(SpecialType.System_String);

                var encodeStringRouteParameters = string.Join(Environment.NewLine, action.Parameters
                    .Where(p => SymbolEqualityComparer.Default.Equals(p.Type, stringType))
                    .Select(p => $"{p.Name} = Uri.EscapeDataString(Uri.UnescapeDataString({p.Name} ?? string.Empty));"));

                generatedMethods.AppendLine($@"
        public async {action.ReturnType.ToDisplayString()} {action.Method.Name}({parameters})
        {{
            {encodeStringRouteParameters}
            {$@"var __url = $""{action.Url}"";"}
            var dynamicQS = GetDynamicQueryString();
            if (dynamicQS is not null)
            {{
                __url += {(action.Url.Contains('?') ? "'&'" : "'?'")} + dynamicQS;
            }}
            {(action.DoesReturnSomething ? $@"return (await prerenderStateService.GetValue(__url, async () =>
            {{" : string.Empty)}
                using var __request = new HttpRequestMessage(HttpMethod.{action.HttpMethod}, __url);
                {requestOptions}
                {(action.BodyParameter is not null ? $@"__request.Content = JsonContent.Create({action.BodyParameter.Name}, options.GetTypeInfo<{action.BodyParameter.Type.ToDisplayString()}>());" : string.Empty)}
                {(action.DoesReturnIAsyncEnumerable ? "" : "using ")}var __response = await httpClient.SendAsync(__request, HttpCompletionOption.ResponseHeadersRead {(action.HasCancellationToken ? $", {action.CancellationTokenParameterName}" : string.Empty)});
                {(action.DoesReturnSomething ? ($"return {(action.DoesReturnIAsyncEnumerable ? "" : "await")} __response.Content.{(action.DoesReturnIAsyncEnumerable ? "ReadFromJsonAsAsyncEnumerable" : action.DoesReturnString ? "ReadAsStringAsync" : "ReadFromJsonAsync")}({jsonReadParameters});" +
          $"}}))!;") : string.Empty)}
        }}
");
            }

            generatedClasses.AppendLine($@"
    internal class {iController.ClassName}(HttpClient httpClient, JsonSerializerOptions options, IPrerenderStateService prerenderStateService) : AppControllerBase, {iController.Symbol.ToDisplayString()}
    {{
        {generatedMethods}
    }}");
        }

        StringBuilder finalSource = new(@$"
using System.Web;
using System.Text.Json;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

[global::System.CodeDom.Compiler.GeneratedCode(""Bit.SourceGenerators"",""{BitSourceGeneratorUtil.GetPackageVersion()}"")]
[global::System.Diagnostics.DebuggerNonUserCode]
[global::System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public static class IHttpClientServiceCollectionExtensions
{{
    public static void AddTypedHttpClients(this IServiceCollection services)
    {{
{string.Join(Environment.NewLine, receiver.IControllers.Select(i => $"        services.TryAddTransient<{i.Symbol.ToDisplayString()}, {i.ClassName}>();"))}
    }}

internal class AppControllerBase
{{
    AppQueryStringCollection queryString = [];

    public void AddQueryString(string key, object? value)
    {{
        queryString.Add(key, value?.ToString());
    }}

    public void AddQueryStrings(Dictionary<string, object?> queryString)
    {{
        foreach (var key in queryString.Keys)
        {{
            AddQueryString(key, queryString[key]);
        }}
    }}

    protected string? GetDynamicQueryString()
    {{
        var result = queryString.ToString();

        queryString.Clear();

        return result;
    }}
}}

{generatedClasses}

}}
");
        context.AddSource($"HttpClientProxy.cs", finalSource.ToString());
    }
}
