using Microsoft.Azure.Functions.Worker.Middleware;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions.Abstract;

/// <summary>
/// Validates bearer tokens for HTTP-triggered Azure Functions before invoking the function.
/// </summary>
public interface IJwtAuthMiddleware : IFunctionsWorkerMiddleware
{
}
