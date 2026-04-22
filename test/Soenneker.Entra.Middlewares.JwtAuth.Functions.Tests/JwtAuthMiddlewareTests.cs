using Soenneker.Tests.HostedUnit;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class JwtAuthMiddlewareTests : HostedUnitTest
{
    public JwtAuthMiddlewareTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {
    }
}