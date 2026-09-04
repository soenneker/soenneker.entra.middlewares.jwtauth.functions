using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Soenneker.Entra.Middlewares.JwtAuth.Functions.Abstract;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.HttpRequestDatas;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
using Soenneker.Extensions.ValueTask;
using System;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Soenneker.Functions.Attributes.AllowAnonymous;
using HttpRequestData = Microsoft.Azure.Functions.Worker.Http.HttpRequestData;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions;

/// <inheritdoc cref="IJwtAuthMiddleware" />
public sealed class JwtAuthMiddleware : IJwtAuthMiddleware
{
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _cfgMgr;
    private readonly TokenValidationParameters _baseParams;

    private readonly ILogger<JwtAuthMiddleware> _logger;
    private readonly string _expectedAzpOrAppId;
    private readonly bool _enableVerboseLogging;

    private static readonly ConcurrentDictionary<string, bool> _allowAnonCache = new(StringComparer.Ordinal);

    public JwtAuthMiddleware(IConfiguration config, ILogger<JwtAuthMiddleware> logger)
    {
        _logger = logger;

        // Default to the official Entra Extensions caller app id unless overridden:
        // https://learn.microsoft.com/azure/active-directory/external-identities/custom-authentication-extension-secure-rest-api
        _expectedAzpOrAppId = config.GetValue<string>("Jwt:ExpectedAzpOrAppId") ?? "99045fe1-7639-4a75-9d4a-577b6ca3810f";

        // Enable verbose logging flag - defaults to false for performance
        _enableVerboseLogging = config.GetValue<bool>("Jwt:EnableVerboseLogging");

        if (_enableVerboseLogging)
        {
            _logger.LogDebug("JWT Auth Middleware initialized with expected Azp/AppId: {ExpectedAzpOrAppId}", _expectedAzpOrAppId);
        }

        string meta = config.GetValueStrict<string>("Jwt:MetadataAddress");

        if (!Uri.TryCreate(meta, UriKind.Absolute, out Uri? metadataUri) || metadataUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Jwt:MetadataAddress must be an absolute HTTPS URL.");

        string[] issuers = config.GetValue<string[]>("Jwt:ValidIssuers") ?? [];
        string[] audiences = config.GetValue<string[]>("Jwt:ValidAudiences") ?? [];
        string[] algorithms = config.GetValue<string[]>("Jwt:ValidAlgorithms") ?? [SecurityAlgorithms.RsaSha256];

        if (issuers.Length == 0)
            throw new InvalidOperationException("Jwt:ValidIssuers must contain at least one issuer.");

        if (audiences.Length == 0)
            throw new InvalidOperationException("Jwt:ValidAudiences must contain at least one audience.");

        if (algorithms.Length == 0)
            throw new InvalidOperationException("Jwt:ValidAlgorithms must contain at least one signing algorithm.");

        TimeSpan skew = TimeSpan.FromSeconds(config.GetValue<int?>("Jwt:ClockSkewSeconds") ?? config.GetValue<int?>("ClockSkewSeconds") ?? 120);

        _logger.LogInformation(
            "Initializing JWT configuration - Metadata: {MetadataAddress}, Issuers: {IssuerCount}, Audiences: {AudienceCount}, ClockSkew: {ClockSkew}s",
            meta, issuers.Length, audiences.Length, skew.TotalSeconds);

        var retriever = new HttpDocumentRetriever { RequireHttps = true };

        _cfgMgr = new ConfigurationManager<OpenIdConnectConfiguration>(meta, new OpenIdConnectConfigurationRetriever(), retriever);

        _baseParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidIssuers = issuers,
            ValidateAudience = true,
            ValidAudiences = audiences,
            ValidateLifetime = true,
            ClockSkew = skew,
            ValidAlgorithms = algorithms
        };

        if (_enableVerboseLogging)
        {
            _logger.LogDebug("JWT configuration initialized successfully");
        }
    }

    public async Task Invoke(FunctionContext ctx, FunctionExecutionDelegate next)
    {
        HttpRequestData? req = await ctx.GetHttpRequestDataAsync()
                                        .NoSync();

        if (req is null)
        {
            if (_enableVerboseLogging)
                _logger.LogDebug("Non-HTTP trigger detected, skipping JWT validation");

            await next(ctx)
                .NoSync();
            return;
        }

        if (HasAllowAnonymousAttribute(ctx))
        {
            if (_enableVerboseLogging)
                _logger.LogDebug("JWT middleware bypassed via [AllowAnonymousFunction] for: {Name}", ctx.FunctionDefinition.Name);

            await next(ctx)
                .NoSync();
            return;
        }

        if (!req.TryGetBearer(out ReadOnlySpan<char> tokenSpan, out _))
        {
            _logger.LogWarning("Missing Bearer token - Function: {Function}, Method: {Method}", ctx.FunctionDefinition.Name, req.Method);
            await req.WriteUnauthorized("Missing Bearer token")
                     .NoSync();
            return;
        }

        var jwt = tokenSpan.ToString();

        if (_enableVerboseLogging)
        {
            _logger.LogDebug("Bearer token found, length: {TokenLength}", jwt.Length);
        }

        try
        {
            if (_enableVerboseLogging)
            {
                _logger.LogDebug("Retrieving OpenID Connect configuration");
            }

            OpenIdConnectConfiguration cfg = await _cfgMgr.GetConfigurationAsync(ctx.CancellationToken)
                                                           .NoSync();

            TokenValidationParameters tvp = _baseParams.Clone();

            string? kid = TryReadKid(jwt);
            if (kid.HasContent())
            {
                if (_enableVerboseLogging)
                {
                    _logger.LogDebug("JWT contains Key ID: {Kid}", kid);
                }

                SecurityKey? match = cfg.SigningKeys.FirstOrDefault(k => string.Equals(k.KeyId, kid, StringComparison.Ordinal));
                tvp.IssuerSigningKeys = match is not null ? [match] : cfg.SigningKeys;

                if (_enableVerboseLogging)
                {
                    if (match is not null)
                    {
                        _logger.LogDebug("Found matching signing key for Kid: {Kid}", kid);
                    }
                    else
                    {
                        _logger.LogDebug("No matching signing key found for Kid: {Kid}, using all available keys", kid);
                    }
                }
            }
            else
            {
                if (_enableVerboseLogging)
                {
                    _logger.LogDebug("JWT does not contain Key ID, using all available signing keys");
                }

                tvp.IssuerSigningKeys = cfg.SigningKeys;
            }

            ClaimsPrincipal principal;

            try
            {
                if (_enableVerboseLogging)
                {
                    _logger.LogDebug("Validating JWT token");
                }

                principal = _handler.ValidateToken(jwt, tvp, out _);

                if (_enableVerboseLogging)
                {
                    _logger.LogDebug("JWT token validation successful");
                }
            }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                _logger.LogWarning("Security token signature key not found, refreshing configuration and retrying");
                _cfgMgr.RequestRefresh();
                cfg = await _cfgMgr.GetConfigurationAsync(ctx.CancellationToken)
                                   .NoSync();
                tvp = _baseParams.Clone();
                tvp.IssuerSigningKeys = cfg.SigningKeys;
                principal = _handler.ValidateToken(jwt, tvp, out _);

                if (_enableVerboseLogging)
                {
                    _logger.LogDebug("JWT token validation successful after configuration refresh");
                }
            }

            // ***** Entra External ID hard requirement *****
            // For v2 tokens expect azp; for v1 tokens expect appid. One of them MUST equal the known caller app id.
            if (!AzpOrAppIdValid(principal, _expectedAzpOrAppId))
            {
                string? azp = principal.FindFirst("azp")
                                       ?.Value;
                string? appid = principal.FindFirst("appid")
                                         ?.Value;

                _logger.LogWarning("Invalid caller (azp/appid) - Expected: {Expected}, Found azp: {Azp}, Found appid: {Appid}", _expectedAzpOrAppId,
                    azp ?? "null", appid ?? "null");

                await req.WriteUnauthorized("Invalid caller (azp/appid)")
                         .NoSync();
                return;
            }

            if (_enableVerboseLogging)
            {
                _logger.LogDebug("Azp/AppId validation successful");
            }

            // Optional: stash the principal for downstream functions
            ctx.Items["User"] = principal;

            _logger.LogInformation("JWT authentication successful - Function: {Function}, Method: {Method}", ctx.FunctionDefinition.Name, req.Method);

            await next(ctx)
                .NoSync();
        }
        catch (OperationCanceledException) when (ctx.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "JWT validation failed - Function: {Function}, Method: {Method}", ctx.FunctionDefinition.Name, req.Method);
            await req.WriteUnauthorized("Unauthorized")
                     .NoSync();
        }
    }

    private static bool AzpOrAppIdValid(ClaimsPrincipal principal, string expected)
    {
        // No allocations beyond two FindFirst string comparisons.
        string? azp = principal.FindFirst("azp")
                               ?.Value;

        if (azp.HasContent() && azp.EqualsIgnoreCase(expected))
            return true;

        string? appid = principal.FindFirst("appid")
                                 ?.Value;

        if (appid.HasContent() && appid.EqualsIgnoreCase(expected))
            return true;

        return false;
    }

    private string? TryReadKid(string jwt)
    {
        try
        {
            JwtSecurityToken? tok = _handler.ReadJwtToken(jwt);
            return tok.Header?.Kid;
        }
        catch
        {
            return null;
        }
    }


    private static bool HasAllowAnonymousAttribute(FunctionContext ctx)
    {
        FunctionDefinition? def = ctx.FunctionDefinition;
        string? entryPoint = def?.EntryPoint; // e.g. "My.Namespace.MyClass.RunAsync"

        if (entryPoint.IsNullOrEmpty())
            return false;

        // Cache on entryPoint string (unique per function)
        if (_allowAnonCache.TryGetValue(entryPoint, out bool cached))
            return cached;

        int lastDot = entryPoint.LastIndexOf('.');
        if (lastDot < 1)
            return _allowAnonCache[entryPoint] = false;

        string typeName = entryPoint[..lastDot];
        string methodName = entryPoint[(lastDot + 1)..];

        // Resolve the type from already-loaded assemblies (fast, no file IO)
        Type? type = null;
        foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            type = asm.GetType(typeName, throwOnError: false, ignoreCase: false);
            if (type is not null)
                break;
        }

        MethodInfo? method = type?.GetMethod(methodName, BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);

        bool hasAttr = method?.GetCustomAttribute<AllowAnonymousFunctionAttribute>() is not null;
        _allowAnonCache[entryPoint] = hasAttr;
        return hasAttr;
    }
}
