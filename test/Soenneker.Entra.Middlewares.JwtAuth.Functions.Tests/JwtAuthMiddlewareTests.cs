using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class JwtAuthMiddlewareTests : HostedUnitTest
{
    public JwtAuthMiddlewareTests(Host host) : base(host)
    {
    }

    [Test]
    public async Task Rejects_non_https_metadata()
    {
        IConfiguration configuration = BuildConfiguration("http://localhost/.well-known/openid-configuration", includeIssuer: true, includeAudience: true);

        await Assert.That(() => new JwtAuthMiddleware(configuration, NullLogger<JwtAuthMiddleware>.Instance)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Rejects_missing_issuers()
    {
        IConfiguration configuration = BuildConfiguration("https://login.example.com/.well-known/openid-configuration", includeIssuer: false,
            includeAudience: true);

        await Assert.That(() => new JwtAuthMiddleware(configuration, NullLogger<JwtAuthMiddleware>.Instance)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Rejects_missing_audiences()
    {
        IConfiguration configuration = BuildConfiguration("https://login.example.com/.well-known/openid-configuration", includeIssuer: true,
            includeAudience: false);

        await Assert.That(() => new JwtAuthMiddleware(configuration, NullLogger<JwtAuthMiddleware>.Instance)).Throws<InvalidOperationException>();
    }

    private static IConfiguration BuildConfiguration(string metadataAddress, bool includeIssuer, bool includeAudience)
    {
        var values = new Dictionary<string, string?>
        {
            ["Jwt:MetadataAddress"] = metadataAddress
        };

        if (includeIssuer)
            values["Jwt:ValidIssuers:0"] = "https://issuer.example.com";

        if (includeAudience)
            values["Jwt:ValidAudiences:0"] = "api://example";

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }
}
