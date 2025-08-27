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
    // Reuse handler to avoid per-request allocs
    private static readonly JwtSecurityTokenHandler _handler = new();

    // Shared config manager and base TVP (immutable parts)
    private static ConfigurationManager<OpenIdConnectConfiguration>? _cfgMgr;
    private static TokenValidationParameters? _baseParams;

    private readonly ILogger<JwtAuthMiddleware> _log;

    public JwtAuthMiddleware(IConfiguration config, ILogger<JwtAuthMiddleware> log)
    {
        _log = log;

        if (_cfgMgr is null || _baseParams is null)
        {
            string meta = config.GetValueStrict<string>("Jwt:MetadataAddress") ?? throw new InvalidOperationException("Jwt:MetadataAddress is required");

            string[] issuers = config.GetValue<string[]>("Jwt:ValidIssuers") ?? [];
            string[] audiences = config.GetValue<string[]>("Jwt:ValidAudiences") ?? [];
            TimeSpan skew = TimeSpan.FromSeconds(config.GetValue<int?>("ClockSkewSeconds") ?? 120);

            var retriever = new HttpDocumentRetriever
            {
                RequireHttps = meta.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            };

            _cfgMgr = new ConfigurationManager<OpenIdConnectConfiguration>(meta, new OpenIdConnectConfigurationRetriever(), retriever);

            // Build once; we only inject keys per request
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

            // Make claim types pass through unchanged
            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
        }
    }

    public async Task Invoke(FunctionContext ctx, FunctionExecutionDelegate next)
    {
        HttpRequestData? req = await ctx.GetHttpRequestDataAsync().NoSync();

        if (req is null)
        {
            await next(ctx).NoSync(); // non-HTTP trigger
            return;
        }

        if (!req.TryGetBearer(out ReadOnlySpan<char> tokenSpan, out _))
        {
            await req.WriteUnauthorized("Missing Bearer token").NoSync();
            return;
        }

        // JwtSecurityTokenHandler needs a string
        var jwt = tokenSpan.ToString();

        try
        {
            // ConfigManager caches and refreshes under the hood; cheap call on steady-state
            OpenIdConnectConfiguration cfg = await _cfgMgr!.GetConfigurationAsync(ctx.CancellationToken).NoSync();

            // Clone the base so we can safely set per-request state without races
            TokenValidationParameters tvp = _baseParams!.Clone();

            // Fast path: if the token has a 'kid', narrow the keys up-front
            string? kid = TryReadKid(jwt);

            if (kid.HasContent())
            {
                SecurityKey? match = cfg.SigningKeys.FirstOrDefault(k => string.Equals(k.KeyId, kid, StringComparison.Ordinal));

                if (match is not null)
                {
                    tvp.IssuerSigningKeys = [match];
                }
                else
                {
                    // Fall back to all keys; ValidateToken will throw SignatureKeyNotFound and we refresh below
                    tvp.IssuerSigningKeys = cfg.SigningKeys;
                }
            }
            else
            {
                tvp.IssuerSigningKeys = cfg.SigningKeys;
            }

            ClaimsPrincipal principal;

            try
            {
                principal = _handler.ValidateToken(jwt, tvp, out _);
            }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                // Key rotation: force a refresh and retry once
                _cfgMgr.RequestRefresh();
                cfg = await _cfgMgr.GetConfigurationAsync(ctx.CancellationToken).NoSync();
                tvp = _baseParams.Clone();
                tvp.IssuerSigningKeys = cfg.SigningKeys;
                principal = _handler.ValidateToken(jwt, tvp, out _);
            }

            // Optionally expose principal for downstream
            ctx.Items["User"] = principal;

            await next(ctx).NoSync();
        }
        catch (Exception ex)
        {
            // Keep message-only to avoid logging large tokens/PII
            _log.LogWarning("JWT validation failed: {Message}", ex.Message);
            await req.WriteUnauthorized("Unauthorized").NoSync();
        }
    }

    /// <summary>
    /// Very small helper to read the 'kid' header without constructing a full JwtSecurityToken.
    /// JwtSecurityTokenHandler can read headers cheaply.
    /// </summary>
    private static string? TryReadKid(string jwt)
    {
        try
        {
            // ReadJwtToken allocates a JwtSecurityToken but avoids full validation; still cheaper than full parse later
            JwtSecurityToken? tok = _handler.ReadJwtToken(jwt);
            return tok.Header?.Kid;
        }
        catch
        {
            return null;
        }
    }
}