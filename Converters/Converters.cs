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
        var level = value is ThreatLevel tl ? tl : ThreatLevel.Info;
        return level switch
        {
            ThreatLevel.Critical => Brush("#FF4D6D"),
            ThreatLevel.High => Brush("#FF8A4C"),
            ThreatLevel.Medium => Brush("#FFD166"),
            ThreatLevel.Low => Brush("#5BC0EB"),
            _ => Brush("#3DE7C8")
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
