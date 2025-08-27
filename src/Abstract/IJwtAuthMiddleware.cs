using Microsoft.Azure.Functions.Worker.Middleware;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions.Abstract;

/// <summary>
/// Middleware for Azure Functions that validates Microsoft Entra JWTs
/// </summary>
public interface IJwtAuthMiddleware : IFunctionsWorkerMiddleware
{
}
