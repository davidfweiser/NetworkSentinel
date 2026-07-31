using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using NetworkSentinel.Models;

namespace NetworkSentinel.Converters;

public sealed class ThreatLevelToBrushConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        // Severity ramp ported from the iOS app's ThreatSeverity.color
        // (NetworkSentinel-iOS/Models/Models.swift) so a Critical reads the same
        // red on both platforms.
        var level = value is ThreatLevel tl ? tl : ThreatLevel.Info;
        return level switch
        {
            ThreatLevel.Critical => Brush("#F24059"),
            ThreatLevel.High => Brush("#FA7340"),
            ThreatLevel.Medium => Brush("#F2BF40"),
            ThreatLevel.Low => Brush("#59BFF2"),
            _ => Brush("#3BC8B4")
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

    private static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));
}

/// <summary>Converts bool → IsVisible (Avalonia uses bool, not Visibility).</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool flag = value is true;
        if (parameter is string s && s.Equals("Invert", StringComparison.OrdinalIgnoreCase))
            flag = !flag;
        return flag;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true;
}

public sealed class MonitoringToTextConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? "Pause" : "Start";

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class InvertBoolConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is not true;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is not true;
}

/// <summary>True when the bound string has content — used to hide empty status banners.</summary>
public sealed class StringNotEmptyConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => !string.IsNullOrWhiteSpace(value as string);

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
