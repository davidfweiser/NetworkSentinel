using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class LoginThrottleTests
{
    private static TimeSpan FailUntilLocked(LoginThrottle throttle, string client)
    {
        var lockout = TimeSpan.Zero;
        for (var i = 0; i < LoginThrottle.MaxFailures; i++)
            lockout = throttle.RecordFailure(client);
        return lockout;
    }

    [Fact]
    public void FewerThanTheLimitDoesNotLock()
    {
        var throttle = new LoginThrottle();

        for (var i = 0; i < LoginThrottle.MaxFailures - 1; i++)
            Assert.Equal(TimeSpan.Zero, throttle.RecordFailure("203.0.113.7"));

        Assert.False(throttle.IsLocked("203.0.113.7", out _));
    }

    [Fact]
    public void SignInLockoutDoublesWithEachFurtherFailure()
    {
        var throttle = new LoginThrottle();

        Assert.Equal(TimeSpan.FromMinutes(1), FailUntilLocked(throttle, "203.0.113.7"));
        Assert.Equal(TimeSpan.FromMinutes(2), throttle.RecordFailure("203.0.113.7"));
        Assert.Equal(TimeSpan.FromMinutes(4), throttle.RecordFailure("203.0.113.7"));
        Assert.True(throttle.IsLocked("203.0.113.7", out var wait));
        Assert.True(wait > TimeSpan.FromMinutes(3));
    }

    [Fact]
    public void CappedLockoutStaysAtItsCeiling()
    {
        // What the token API uses: a bot retrying a replaced token must not dig
        // itself into an hour-long hole before the new one is pasted in.
        var throttle = new LoginThrottle(maxLockout: TimeSpan.FromMinutes(1));

        Assert.Equal(TimeSpan.FromMinutes(1), FailUntilLocked(throttle, "203.0.113.7"));
        for (var i = 0; i < 12; i++)
            Assert.Equal(TimeSpan.FromMinutes(1), throttle.RecordFailure("203.0.113.7"));
    }

    [Fact]
    public void OneClientsFailuresDoNotLockAnother()
    {
        var throttle = new LoginThrottle();
        FailUntilLocked(throttle, "203.0.113.7");

        Assert.True(throttle.IsLocked("203.0.113.7", out _));
        Assert.False(throttle.IsLocked("203.0.113.8", out _));
    }
}
