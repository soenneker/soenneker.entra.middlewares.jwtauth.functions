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
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using HttpRequestData = Microsoft.Azure.Functions.Worker.Http.HttpRequestData;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions;

/// <inheritdoc cref="IJwtAuthMiddleware"/>
public sealed class JwtAuthMiddleware : IJwtAuthMiddleware
{
    private static readonly JwtSecurityTokenHandler _handler = new();

    private static ConfigurationManager<OpenIdConnectConfiguration>? _cfgMgr;
    private static TokenValidationParameters? _baseParams;

    private readonly ILogger<JwtAuthMiddleware> _logger;
    private readonly string _expectedAzpOrAppId;
    private readonly bool _enableVerboseLogging;

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

        if (_cfgMgr is null || _baseParams is null)
        {
            string meta = config.GetValueStrict<string>("Jwt:MetadataAddress") ?? throw new InvalidOperationException("Jwt:MetadataAddress is required");

            string[] issuers = config.GetValue<string[]>("Jwt:ValidIssuers") ?? [];
            string[] audiences = config.GetValue<string[]>("Jwt:ValidAudiences") ?? [];
            TimeSpan skew = TimeSpan.FromSeconds(config.GetValue<int?>("ClockSkewSeconds") ?? 120);

            _logger.LogInformation("Initializing JWT configuration - Metadata: {MetadataAddress}, Issuers: {IssuerCount}, Audiences: {AudienceCount}, ClockSkew: {ClockSkew}s", 
                meta, issuers.Length, audiences.Length, skew.TotalSeconds);

            var retriever = new HttpDocumentRetriever
            {
                RequireHttps = meta.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            };

            _cfgMgr = new ConfigurationManager<OpenIdConnectConfiguration>(meta, new OpenIdConnectConfigurationRetriever(), retriever);

            _baseParams = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = issuers.Length > 0,
                ValidIssuers = issuers,
                ValidateAudience = audiences.Length > 0,
                ValidAudiences = audiences,
                ValidateLifetime = true,
                ClockSkew = skew
            };

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            if (_enableVerboseLogging)
            {
                _logger.LogDebug("JWT configuration initialized successfully");
            }
        }
    }

    public async Task Invoke(FunctionContext ctx, FunctionExecutionDelegate next)
    {
        HttpRequestData? req = await ctx.GetHttpRequestDataAsync().NoSync();

        if (req is null)
        {
            if (_enableVerboseLogging)
            {
                _logger.LogDebug("Non-HTTP trigger detected, skipping JWT validation");
            }
            await next(ctx).NoSync(); // non-HTTP trigger
            return;
        }

        if (_enableVerboseLogging)
        {
            _logger.LogDebug("Processing HTTP request for JWT validation - Method: {Method}, URL: {Url}", 
                req.Method, req.Url?.ToString());
        }

        if (!req.TryGetBearer(out ReadOnlySpan<char> tokenSpan, out _))
        {
            _logger.LogWarning("Missing Bearer token in request - Method: {Method}, URL: {Url}", 
                req.Method, req.Url?.ToString());
            await req.WriteUnauthorized("Missing Bearer token").NoSync();
            return;
        }

        string jwt = tokenSpan.ToString();
        
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
            
            OpenIdConnectConfiguration cfg = await _cfgMgr!.GetConfigurationAsync(ctx.CancellationToken).NoSync();

            TokenValidationParameters tvp = _baseParams!.Clone();

            string? kid = TryReadKid(jwt);
            if (kid.HasContent())
            {
                if (_enableVerboseLogging)
                {
                    _logger.LogDebug("JWT contains Key ID: {Kid}", kid);
                }
                
                SecurityKey? match = cfg.SigningKeys.FirstOrDefault(k => string.Equals(k.KeyId, kid, StringComparison.Ordinal));
                tvp.IssuerSigningKeys = match is not null ? new[] {match} : cfg.SigningKeys;
                
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
                cfg = await _cfgMgr.GetConfigurationAsync(ctx.CancellationToken).NoSync();
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
                var azp = principal.FindFirst("azp")?.Value;
                var appid = principal.FindFirst("appid")?.Value;
                
                _logger.LogWarning("Invalid caller (azp/appid) - Expected: {Expected}, Found azp: {Azp}, Found appid: {Appid}", 
                    _expectedAzpOrAppId, azp ?? "null", appid ?? "null");
                
                await req.WriteUnauthorized("Invalid caller (azp/appid)").NoSync();
                return;
            }

            if (_enableVerboseLogging)
            {
                _logger.LogDebug("Azp/AppId validation successful");
            }

            // Optional: stash the principal for downstream functions
            ctx.Items["User"] = principal;

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value ?? "unknown";
            var userEmail = principal.FindFirst(ClaimTypes.Email)?.Value ?? principal.FindFirst("email")?.Value ?? "unknown";
            
            _logger.LogInformation("JWT authentication successful - User: {UserId}, Email: {UserEmail}, Method: {Method}, URL: {Url}", 
                userId, userEmail, req.Method, req.Url?.ToString());

            await next(ctx).NoSync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "JWT validation failed - Method: {Method}, URL: {Url}, Error: {Message}", 
                req.Method, req.Url?.ToString(), ex.Message);
            await req.WriteUnauthorized("Unauthorized").NoSync();
        }
    }

    private static bool AzpOrAppIdValid(ClaimsPrincipal principal, string expected)
    {
        // No allocations beyond two FindFirst string comparisons.
        string? azp = principal.FindFirst("azp")?.Value;
        if (azp.HasContent() && string.Equals(azp, expected, StringComparison.OrdinalIgnoreCase))
            return true;

        string? appid = principal.FindFirst("appid")?.Value;
        if (appid.HasContent() && string.Equals(appid, expected, StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    private static string? TryReadKid(string jwt)
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
}