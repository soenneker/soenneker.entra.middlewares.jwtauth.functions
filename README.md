[![](https://img.shields.io/nuget/v/soenneker.entra.middlewares.jwtauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.entra.middlewares.jwtauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.entra.middlewares.jwtauth.functions/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.entra.middlewares.jwtauth.functions/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.entra.middlewares.jwtauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.entra.middlewares.jwtauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.entra.middlewares.jwtauth.functions/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.entra.middlewares.jwtauth.functions/actions/workflows/codeql.yml)

# Soenneker.Entra.Middlewares.JwtAuth.Functions

Middleware for Azure Functions that validates Microsoft Entra JWTs.

## Install

```bash
dotnet add package Soenneker.Entra.Middlewares.JwtAuth.Functions
```

## Quick start

```csharp
using Soenneker.Entra.Middlewares.JwtAuth.Functions.Registrars;

IFunctionsWorkerApplicationBuilder builder = /* obtain from your application */;
var result = builder.UseEntraFunctionsJwtAuth();
```

Registers `JwtAuthMiddleware` into the Functions worker pipeline.

## What you get

- `IJwtAuthMiddleware` — Middleware for Azure Functions that validates Microsoft Entra JWTs.
- `JwtAuthMiddlewareRegistrar` — Middleware for Azure Functions that validates Microsoft Entra JWTs.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `JwtAuthMiddlewareRegistrar.UseEntraFunctionsJwtAuth(builder)` | Registers `JwtAuthMiddleware` into the Functions worker pipeline. | The same builder instance, so additional classes or variants can be chained. |
