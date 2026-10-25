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

    [Fact]
    public void ParallelGuessesAreCutOffAtTheLimit()
    {
        // Every attempt is counted before the (slow) password check, so a burst that
        // arrives all at once gets MaxFailures guesses, not one per server thread.
        var throttle = new LoginThrottle();
        var admitted = 0;
        Parallel.For(0, 200, i =>
        {
            if (throttle.TryBeginAttempt("203.0.113.8", out _, out _))
                Interlocked.Increment(ref admitted);
        });

        Assert.Equal(LoginThrottle.MaxFailures, admitted);
        Assert.True(throttle.IsLocked("203.0.113.8", out _));
    }

    [Fact]
    public void ARightGuessClearsTheAttemptItCounted()
    {
        var throttle = new LoginThrottle();
        for (var i = 0; i < 10; i++)
        {
            Assert.True(throttle.TryBeginAttempt("203.0.113.9", out _, out _));
            throttle.RecordSuccess("203.0.113.9");
        }
        Assert.False(throttle.IsLocked("203.0.113.9", out _));
    }

    [Fact]
    public void TheLastAdmittedGuessKnowsTheLockoutItWouldTrigger()
    {
        var throttle = new LoginThrottle();
        var lockout = TimeSpan.Zero;
        for (var i = 0; i < LoginThrottle.MaxFailures; i++)
            Assert.True(throttle.TryBeginAttempt("203.0.113.10", out _, out lockout));

        Assert.True(lockout > TimeSpan.Zero);
        Assert.False(throttle.TryBeginAttempt("203.0.113.10", out var retryAfter, out _));
        Assert.True(retryAfter > TimeSpan.Zero);
    }
}
