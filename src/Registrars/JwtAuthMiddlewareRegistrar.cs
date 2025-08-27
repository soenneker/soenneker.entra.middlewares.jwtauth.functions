using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Hosting;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions.Registrars;

/// <summary>
/// Middleware for Azure Functions that validates Microsoft Entra JWTs
/// </summary>
public static class JwtAuthMiddlewareRegistrar
{
    /// <summary>
    /// Registers <see cref="JwtAuthMiddleware"/> into the Functions worker pipeline.
    /// </summary>
    public static IFunctionsWorkerApplicationBuilder UseEntraFunctionsJwtAuth(this IFunctionsWorkerApplicationBuilder builder)
    {
        builder.UseMiddleware<JwtAuthMiddleware>();

        return builder;
    }
}
