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

    private readonly ILogger<JwtAuthMiddleware> _log;
    private readonly string _expectedAzpOrAppId;

    public JwtAuthMiddleware(IConfiguration config, ILogger<JwtAuthMiddleware> log)
    {
        _log = log;

        // Default to the official Entra Extensions caller app id unless overridden:
        // https://learn.microsoft.com/azure/active-directory/external-identities/custom-authentication-extension-secure-rest-api
        _expectedAzpOrAppId = config.GetValue<string>("Jwt:ExpectedAzpOrAppId") ?? "99045fe1-7639-4a75-9d4a-577b6ca3810f";

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

        string jwt = tokenSpan.ToString();

        try
        {
            OpenIdConnectConfiguration cfg = await _cfgMgr!.GetConfigurationAsync(ctx.CancellationToken).NoSync();

            TokenValidationParameters tvp = _baseParams!.Clone();

            string? kid = TryReadKid(jwt);
            if (kid.HasContent())
            {
                SecurityKey? match = cfg.SigningKeys.FirstOrDefault(k => string.Equals(k.KeyId, kid, StringComparison.Ordinal));
                tvp.IssuerSigningKeys = match is not null ? new[] {match} : cfg.SigningKeys;
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
                _cfgMgr.RequestRefresh();
                cfg = await _cfgMgr.GetConfigurationAsync(ctx.CancellationToken).NoSync();
                tvp = _baseParams.Clone();
                tvp.IssuerSigningKeys = cfg.SigningKeys;
                principal = _handler.ValidateToken(jwt, tvp, out _);
            }

            // ***** Entra External ID hard requirement *****
            // For v2 tokens expect azp; for v1 tokens expect appid. One of them MUST equal the known caller app id.
            if (!AzpOrAppIdValid(principal, _expectedAzpOrAppId))
            {
                await req.WriteUnauthorized("Invalid caller (azp/appid)").NoSync();
                return;
            }

            // Optional: stash the principal for downstream functions
            ctx.Items["User"] = principal;

            await next(ctx).NoSync();
        }
        catch (Exception ex)
        {
            _log.LogWarning("JWT validation failed: {Message}", ex.Message);
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