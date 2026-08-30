[![](https://img.shields.io/nuget/v/soenneker.entra.middlewares.jwtauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.entra.middlewares.jwtauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.entra.middlewares.jwtauth.functions/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.entra.middlewares.jwtauth.functions/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.entra.middlewares.jwtauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.entra.middlewares.jwtauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.entra.middlewares.jwtauth.functions/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.entra.middlewares.jwtauth.functions/actions/workflows/codeql.yml)

# Soenneker.Entra.Middlewares.JwtAuth.Functions

Bearer-token authentication middleware for .NET isolated Azure Functions using Microsoft Entra OpenID Connect metadata and signing keys.

## Install

```bash
dotnet add package Soenneker.Entra.Middlewares.JwtAuth.Functions
```

## Configuration

```json
{
  "Jwt": {
    "MetadataAddress": "https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration",
    "ValidIssuers": [
      "https://login.microsoftonline.com/<tenant-id>/v2.0"
    ],
    "ValidAudiences": [
      "api://<api-application-id>"
    ],
    "ValidAlgorithms": ["RS256"],
    "ExpectedAzpOrAppId": "<authorized-caller-application-id>",
    "ClockSkewSeconds": 120,
    "EnableVerboseLogging": false
  }
}
```

`MetadataAddress`, at least one issuer, and at least one audience are required. The metadata address must be an absolute HTTPS URL. Issuer and audience validation cannot be disabled by supplying empty arrays.

`ValidAlgorithms` defaults to `RS256`; an explicitly empty list is rejected. `ClockSkewSeconds` defaults to 120. Keep skew as small as your deployment's clock synchronization permits.

The middleware also requires either the token's `azp` claim (v2) or `appid` claim (v1) to equal `ExpectedAzpOrAppId`. If that setting is omitted, it defaults to `99045fe1-7639-4a75-9d4a-577b6ca3810f`, the Microsoft Entra External ID custom-authentication-extension caller. Set it explicitly for other callers.

## Register the middleware

```csharp
using Soenneker.Entra.Middlewares.JwtAuth.Functions.Registrars;

builder.UseEntraFunctionsJwtAuth();
```

Register it before middleware or function code that assumes an authenticated principal.

## Read the authenticated principal

After signature, issuer, audience, lifetime, algorithm, and caller-app validation succeeds, the principal is stored in `FunctionContext.Items` under `"User"`:

```csharp
using System.Security.Claims;

if (context.Items.TryGetValue("User", out object? value) &&
    value is ClaimsPrincipal principal)
{
    string? subject = principal.FindFirst("sub")?.Value;
}
```

The middleware authenticates the token; it does not enforce scopes, app roles, tenant-specific business rules, or resource ownership. Perform those authorization checks in downstream middleware or the function.

## Anonymous and non-HTTP functions

All HTTP-triggered functions are protected by default. Mark an individual function method with `AllowAnonymousFunction` to bypass validation:

```csharp
using Soenneker.Functions.Attributes.AllowAnonymous;

[AllowAnonymousFunction]
[Function("Health")]
public HttpResponseData Health(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData request)
{
    return request.CreateResponse(HttpStatusCode.OK);
}
```

The attribute is method-only. Non-HTTP triggers bypass JWT validation automatically.

Missing, malformed, expired, incorrectly signed, wrong-issuer, wrong-audience, wrong-algorithm, or wrong-caller tokens receive an unauthorized response and the function is not invoked. OpenID configuration is cached per middleware instance and refreshed when a signing key is not found.

Verbose logging reports validation flow and key identifiers but never logs the bearer token. Successful authentication logs only the function and HTTP method; claims and request URLs are not written at information level.
