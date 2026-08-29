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
    /// <param name="builder">Builder to configure.</param>
    /// <returns>The same builder instance, so additional classes or variants can be chained.</returns>
    public static IFunctionsWorkerApplicationBuilder UseEntraFunctionsJwtAuth(this IFunctionsWorkerApplicationBuilder builder)
    {
        builder.UseMiddleware<JwtAuthMiddleware>();

        return builder;
    }
}
