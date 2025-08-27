using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Entra.Middlewares.JwtAuth.Functions.Tests;

[Collection("Collection")]
public sealed class JwtAuthMiddlewareTests : FixturedUnitTest
{
    public JwtAuthMiddlewareTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {
    }
}