using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The web console's defences that do not depend on the password: where it
/// listens, which origins may change state, what script the page may run, and
/// how long a session lasts.
/// </summary>
public class WebConsoleHardeningTests
{
    // ---- Cross-site requests ----------------------------------------------------

    [Theory]
    [InlineData("POST", "cross-site", null, "box:18765")]
    [InlineData("POST", "same-site", null, "box:18765")]          // another port on the same host
    [InlineData("POST", null, "http://box:8080", "box:18765")]     // older browser: Origin only
    [InlineData("POST", null, "https://evil.example", "box:18765")]
    [InlineData("POST", null, "null", "box:18765")]                // sandboxed frame / file://
    [InlineData("DELETE", "cross-site", null, "box:18765")]
    public void CrossOriginWritesAreRefused(string method, string? site, string? origin, string host)
        => Assert.True(WebApp.IsCrossSiteRequest(method, site, origin, host));

    [Theory]
    [InlineData("POST", "same-origin", "http://box:18765", "box:18765")]
    [InlineData("POST", null, "http://box:18765", "box:18765")]
    [InlineData("POST", null, "https://sentinel.example.com", "sentinel.example.com")] // behind a TLS proxy
    [InlineData("POST", null, null, "box:18765")]                  // curl, the iOS app, a token bot
    [InlineData("GET", "cross-site", "https://evil.example", "box:18765")]
    public void SameOriginAndNonBrowserRequestsPass(string method, string? site, string? origin, string host)
        => Assert.False(WebApp.IsCrossSiteRequest(method, site, origin, host));

    // ---- Content-Security-Policy ------------------------------------------------

    [Fact]
    public void ThePolicyAdmitsThePagesOwnScriptByHash()
    {
        var html = WebApp.IndexHtml.Replace("__NS_VERSION__", "0.0.0-test");
        var csp = WebApp.BuildContentSecurityPolicy(html);

        var script = Regex.Match(html, "<script>(.*?)</script>", RegexOptions.Singleline).Groups[1].Value;
        var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(script)));

        Assert.Contains($"script-src 'sha256-{hash}';", csp);
        Assert.DoesNotContain("unsafe-inline';", csp.Split("style-src")[0]);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("connect-src 'self'", csp);
    }

    [Fact]
    public void ThePageCarriesNothingAHashCannotCover()
    {
        // An inline handler attribute or a second, external script would be blocked by
        // the policy and break the page; event handlers are assigned from the script.
        var html = WebApp.IndexHtml;
        Assert.Single(Regex.Matches(html, "<script"));
        Assert.DoesNotMatch(@"<[^>]+\son[a-z]+\s*=", html);
    }

    // ---- --bind -----------------------------------------------------------------

    [Theory]
    [InlineData("localhost", "127.0.0.1")]
    [InlineData("all", "0.0.0.0")]
    [InlineData("*", "0.0.0.0")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::", "::")]
    [InlineData("[::1]", "::1")]
    [InlineData(" 100.64.0.7 ", "100.64.0.7")]
    public void BindAddressesParse(string value, string expected)
    {
        Assert.True(Program.TryParseBindAddress(value, out var address));
        Assert.Equal(IPAddress.Parse(expected), address);
    }

    [Theory]
    [InlineData("lan")]
    [InlineData("box.example.com")]
    [InlineData("")]
    public void UnknownBindAddressesAreRejected(string value)
        => Assert.False(Program.TryParseBindAddress(value, out _));

    // ---- Session lifetime -------------------------------------------------------

    [Fact]
    public void ABusySessionStillEndsAtItsMaximumAge()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var store = new WebAuthStore(dir) { UtcNow = () => now };
            var token = store.CreateSession();

            // An open tab polls every few seconds; step through a week of that an hour at a time.
            for (var elapsed = TimeSpan.Zero; elapsed < WebAuthStore.SessionMaxAge; elapsed += TimeSpan.FromHours(1))
            {
                now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc) + elapsed;
                Assert.True(store.IsSessionValid(token));
            }

            now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc) + WebAuthStore.SessionMaxAge + TimeSpan.FromMinutes(1);
            Assert.False(store.IsSessionValid(token));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AnIdleSessionStillEndsAfterTwelveHours()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var store = new WebAuthStore(dir) { UtcNow = () => now };
            var token = store.CreateSession();

            now += TimeSpan.FromHours(12) + TimeSpan.FromMinutes(1);
            Assert.False(store.IsSessionValid(token));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
