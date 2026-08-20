using NetworkSentinel.Services;
using NetworkSentinel.Tui;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The TUI's Settings catalogue: the rows the eighth view lists, and the invariants
/// the view assumes about them.
///
/// Every row carries its own Read delegate reaching into a live service, so a row
/// wired to a property that is null, missing or of the wrong shape does not fail at
/// build time — it fails the first time somebody opens Settings over a remote
/// session, which is the one place there is no other front-end to fall back to.
/// Reading the whole catalogue here is what makes that a build-time failure instead.
///
/// Only reads are exercised. Applying a row is deliberately left alone: the
/// closed-port toggle shells out to netsh, and traffic metering starts a timer.
/// </summary>
public class TuiSettingsTests
{
    /// <summary>
    /// The service graph the catalogue binds to. Constructing it is cheap and inert —
    /// the detector setters only start anything once the monitor is running, and it
    /// never is here. Settings are passed in rather than loaded, so the suite reads
    /// no state from the machine it runs on.
    /// </summary>
    private static SentinelCore Core() => new(new AppSettings());

    [Fact]
    public void EveryRow_CarriesASectionLabelAndDescription()
    {
        using var core = Core();
        var items = new TuiSettings(core).Items;

        Assert.NotEmpty(items);
        foreach (var item in items)
        {
            Assert.False(string.IsNullOrWhiteSpace(item.Section), $"Row '{item.Label}' has no section.");
            Assert.False(string.IsNullOrWhiteSpace(item.Label), "A row has no label.");
            Assert.False(string.IsNullOrWhiteSpace(item.Description), $"Row '{item.Label}' has no description.");
        }
    }

    /// <summary>
    /// Drawing the view calls Read on every visible row. One that throws takes the
    /// whole Live display down rather than showing a bad value.
    /// </summary>
    [Fact]
    public void EveryRow_ReadsWithoutThrowing()
    {
        using var core = Core();
        var items = new TuiSettings(core).Items;

        foreach (var item in items)
        {
            var value = Record.Exception(() => item.Read());
            Assert.True(value == null, $"Row '{item.Label}' threw while reading: {value?.Message}");
        }
    }

    /// <summary>
    /// Enter flips a toggle by reading "on"/"off" back. A row that reports anything
    /// else is read as off and would flip the wrong way on the first press.
    /// </summary>
    [Fact]
    public void ToggleRows_ReadOnOrOff()
    {
        using var core = Core();
        var items = new TuiSettings(core).Items;

        foreach (var item in items.Where(i => i.Kind == SettingKind.Toggle))
            Assert.True(item.Read() is "on" or "off", $"Toggle '{item.Label}' read '{item.Read()}'.");
    }

    /// <summary>
    /// Enter advances a choice by finding the current value in Choices. A value that
    /// is not in the list sends every press back to the first choice, so the row
    /// could never reach the others.
    /// </summary>
    [Fact]
    public void ChoiceRows_ReadAValueFromTheirOwnChoices()
    {
        using var core = Core();
        var items = new TuiSettings(core).Items;

        var choices = items.Where(i => i.Kind == SettingKind.Choice).ToList();
        Assert.NotEmpty(choices);
        foreach (var item in choices)
        {
            Assert.NotEmpty(item.Choices);
            Assert.Contains(item.Read(), item.Choices);
        }
    }

    /// <summary>
    /// The view prints a section once per run of rows, so two rows sharing a section
    /// and a label are two lines the operator cannot tell apart.
    /// </summary>
    [Fact]
    public void RowsAreDistinguishable_WithinASection()
    {
        using var core = Core();
        var items = new TuiSettings(core).Items;

        var duplicates = items
            .GroupBy(i => (i.Section, i.Label))
            .Where(g => g.Count() > 1)
            .Select(g => $"{g.Key.Section}/{g.Key.Label}")
            .ToList();

        Assert.Empty(duplicates);
    }

    /// <summary>
    /// Anything that has to be typed opens a prompt, and the prompt's only guidance
    /// is the hint. A Number or Text row without one asks for a value while saying
    /// nothing about what shape it should take.
    /// </summary>
    [Fact]
    public void TypedRows_CarryAPromptHint()
    {
        using var core = Core();
        var items = new TuiSettings(core).Items;

        foreach (var item in items.Where(i => i.Kind is SettingKind.Number or SettingKind.Text))
            Assert.False(string.IsNullOrWhiteSpace(item.Hint), $"Row '{item.Label}' has no prompt hint.");
    }
}
