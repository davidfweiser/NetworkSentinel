using System.Text.RegularExpressions;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

public class ControlApiTests
{
    [Theory]
    [InlineData("block")]
    [InlineData("unblock")]
    [InlineData("block_port")]
    [InlineData("remove_rule")]
    [InlineData("remove_all_rules")]
    [InlineData("save_config_rule")]
    [InlineData("delete_host_rule")]
    [InlineData("add_allowlist")]
    [InlineData("remove_allowlist")]
    [InlineData("sleep")]
    [InlineData("wake")]
    [InlineData("clear_threats")]
    [InlineData("set_min_level")]
    [InlineData("  BLOCK  ")]
    public void OperationalActionsAreOpenToAControlToken(string action)
    {
        Assert.Null(WebApp.ControlRefusal(action, null));
    }

    [Theory]
    [InlineData("webhookUrl")]
    [InlineData("httpsOnly")]
    [InlineData("httpsEnabled")]
    [InlineData("tlsKeyPath")]
    [InlineData("duckDnsToken")]
    [InlineData("dnsFilterPassword")]
    [InlineData("preventionDryRun")]
    [InlineData("honeypotEnabled")]
    [InlineData("AUTOBLOCKENABLED")]
    [InlineData("")]
    [InlineData(null)]
    public void SettingsStayClosed(string? setting)
    {
        Assert.Contains("Settings", WebApp.ControlRefusal("set_setting", setting));
    }

    [Fact]
    public void TheAutoBlockSwitchIsTheOneSettingABotMaySet()
    {
        // The header button only toggles; a bot has to be able to say which way.
        Assert.Null(WebApp.ControlRefusal("set_setting", "autoBlockEnabled"));
    }

    [Theory]
    [InlineData("api_token_create")]
    [InlineData("api_token_revoke")]
    [InlineData("issue_cert")]
    [InlineData("change-password")]
    [InlineData("no_such_action")]
    [InlineData("")]
    [InlineData(null)]
    public void CredentialsAndEverythingElseStayClosed(string? action)
    {
        Assert.NotNull(WebApp.ControlRefusal(action, null));
    }

    /// <summary>
    /// The list is of what is allowed, so a new console action is closed to tokens until
    /// someone opens it. This makes that a decision rather than an oversight: adding an
    /// action to RunAction fails here until it is either put on the list or named below
    /// as deliberately kept from tokens.
    /// </summary>
    [Fact]
    public void EveryConsoleActionIsEitherOpenOrDeliberatelyClosed()
    {
        var path = TestEnv.RepoFile("Web/WebApp.cs");
        if (path == null) return;

        var source = File.ReadAllText(path);
        var start = source.IndexOf("private ActionResultDto RunAction(", StringComparison.Ordinal);
        var end = source.IndexOf("private object BuildState()", start, StringComparison.Ordinal);
        Assert.True(start > 0 && end > start, "RunAction not found — has it been renamed?");

        // Top-level cases only: the nested switch inside set_setting is indented deeper.
        var consoleActions = Regex.Matches(source[start..end], "^ {16}case \"([a-z_]+)\":", RegexOptions.Multiline)
            .Select(m => m.Groups[1].Value)
            .ToHashSet();
        Assert.True(consoleActions.Count > 20, "The action list looks wrong — did RunAction's layout change?");

        var keptFromTokens = new[] { "issue_cert", "set_setting" };

        Assert.Equal(
            keptFromTokens.OrderBy(a => a),
            consoleActions.Except(WebApp.ControlActions).OrderBy(a => a));

        // Token management is not on either list because it is not here at all: what
        // RunAction cannot do, no caller of RunAction can be talked into doing.
        Assert.DoesNotContain("api_token_", source[start..end]);
        Assert.DoesNotContain("_apiTokens.TryCreate", source[start..end]);

        // And nothing on the list that the console does not actually implement.
        Assert.Empty(WebApp.ControlActions.Except(consoleActions));
    }
}
