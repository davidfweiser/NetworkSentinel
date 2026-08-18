using System.Collections.Specialized;
using System.Globalization;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using NetworkSentinel.Models;

namespace NetworkSentinel.Controls;

/// <summary>
/// Shared plumbing for the data-flow charts: a bound <see cref="System.Collections.ObjectModel.ObservableCollection{T}"/>
/// raises CollectionChanged rather than a property change, so each series
/// property has to be re-subscribed when it is swapped and the control has to
/// redraw when the collection it already holds is refilled.
/// </summary>
public abstract class SeriesControl : FrameworkElement
{
    private readonly Dictionary<DependencyProperty, INotifyCollectionChanged> _subscriptions = new();

    protected void TrackSeries(DependencyProperty property, object? newValue)
    {
        if (_subscriptions.TryGetValue(property, out var old))
        {
            old.CollectionChanged -= OnSeriesChanged;
            _subscriptions.Remove(property);
        }

        if (newValue is INotifyCollectionChanged incc)
        {
            incc.CollectionChanged += OnSeriesChanged;
            _subscriptions[property] = incc;
        }

        InvalidateVisual();
    }

    private void OnSeriesChanged(object? sender, NotifyCollectionChangedEventArgs e)
        => Dispatcher.BeginInvoke(InvalidateVisual, DispatcherPriority.Render);

    /// <summary>Four horizontal guides, matching the connection-activity chart.</summary>
    protected static void DrawGrid(DrawingContext context, double width, double height)
    {
        var pen = new Pen(new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)), 1);
        for (var i = 1; i < 4; i++)
        {
            var y = height * i / 4.0;
            context.DrawLine(pen, new Point(0, y), new Point(width, y));
        }
    }

    protected void DrawPlaceholder(DrawingContext context, double height, string message)
        => context.DrawText(Label(message, 12, new SolidColorBrush(Color.FromArgb(140, 200, 220, 255))),
            new Point(12, height / 2 - 8));

    protected FormattedText Label(string value, double size, Brush brush)
        => new(value, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            new Typeface("Segoe UI"), size, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip);
}

/// <summary>
/// Two throughput series on one zero-based scale — inbound and outbound bytes
/// per second. A shared scale is the point: two independently scaled lines make
/// a trickle of uploads look like a match for a saturated download.
/// </summary>
public sealed class DualSparkline : SeriesControl
{
    public static readonly DependencyProperty InboundProperty =
        DependencyProperty.Register(nameof(Inbound), typeof(IEnumerable<double>), typeof(DualSparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnInboundChanged));

    public static readonly DependencyProperty OutboundProperty =
        DependencyProperty.Register(nameof(Outbound), typeof(IEnumerable<double>), typeof(DualSparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnOutboundChanged));

    public static readonly DependencyProperty InboundStrokeProperty =
        DependencyProperty.Register(nameof(InboundStroke), typeof(Brush), typeof(DualSparkline),
            new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x4A, 0x9E, 0xFF)),
                FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty OutboundStrokeProperty =
        DependencyProperty.Register(nameof(OutboundStroke), typeof(Brush), typeof(DualSparkline),
            new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x3B, 0xC8, 0xB4)),
                FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty InboundFillProperty =
        DependencyProperty.Register(nameof(InboundFill), typeof(Brush), typeof(DualSparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty OutboundFillProperty =
        DependencyProperty.Register(nameof(OutboundFill), typeof(Brush), typeof(DualSparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeThicknessProperty =
        DependencyProperty.Register(nameof(StrokeThickness), typeof(double), typeof(DualSparkline),
            new FrameworkPropertyMetadata(2.2, FrameworkPropertyMetadataOptions.AffectsRender));

    public IEnumerable<double>? Inbound
    {
        get => (IEnumerable<double>?)GetValue(InboundProperty);
        set => SetValue(InboundProperty, value);
    }

    public IEnumerable<double>? Outbound
    {
        get => (IEnumerable<double>?)GetValue(OutboundProperty);
        set => SetValue(OutboundProperty, value);
    }

    public Brush? InboundStroke
    {
        get => (Brush?)GetValue(InboundStrokeProperty);
        set => SetValue(InboundStrokeProperty, value);
    }

    public Brush? OutboundStroke
    {
        get => (Brush?)GetValue(OutboundStrokeProperty);
        set => SetValue(OutboundStrokeProperty, value);
    }

    public Brush? InboundFill
    {
        get => (Brush?)GetValue(InboundFillProperty);
        set => SetValue(InboundFillProperty, value);
    }

    public Brush? OutboundFill
    {
        get => (Brush?)GetValue(OutboundFillProperty);
        set => SetValue(OutboundFillProperty, value);
    }

    public double StrokeThickness
    {
        get => (double)GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    private static void OnInboundChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((DualSparkline)d).TrackSeries(InboundProperty, e.NewValue);

    private static void OnOutboundChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((DualSparkline)d).TrackSeries(OutboundProperty, e.NewValue);

    protected override void OnRender(DrawingContext context)
    {
        base.OnRender(context);

        var w = ActualWidth;
        var h = ActualHeight;
        if (w <= 1 || h <= 1) return;

        DrawGrid(context, w, h);

        var inbound = Inbound?.ToList() ?? new List<double>();
        var outbound = Outbound?.ToList() ?? new List<double>();
        var count = Math.Max(inbound.Count, outbound.Count);
        if (count < 2)
        {
            DrawPlaceholder(context, h, "Measuring throughput…");
            return;
        }

        // Zero baseline and one scale for both directions. The floor keeps an idle
        // link from drawing sampling noise as a mountain range.
        var peak = Math.Max(
            inbound.Count > 0 ? inbound.Max() : 0,
            outbound.Count > 0 ? outbound.Max() : 0);
        var max = Math.Max(1024, peak);

        const double pad = 6;
        var usableH = h - pad * 2;
        var stepX = w / (count - 1);

        // Peak label, so the shared scale is readable rather than implied.
        context.DrawText(
            Label(ByteSize.FormatRate(peak), 10, new SolidColorBrush(Color.FromArgb(150, 200, 220, 255))),
            new Point(4, 2));

        DrawSeries(context, outbound, count, stepX, h, pad, usableH, max, OutboundStroke, OutboundFill);
        DrawSeries(context, inbound, count, stepX, h, pad, usableH, max, InboundStroke, InboundFill);
    }

    private void DrawSeries(DrawingContext context, List<double> values, int count, double stepX,
        double h, double pad, double usableH, double max, Brush? stroke, Brush? fill)
    {
        if (values.Count < 2 || stroke == null) return;

        var points = new Point[values.Count];
        // Right-aligned: a series that is one sample short of the other must not
        // be stretched to the same width, or the two lines drift out of step.
        var offset = count - values.Count;
        for (var i = 0; i < values.Count; i++)
        {
            var norm = Math.Clamp(values[i] / max, 0, 1);
            points[i] = new Point((i + offset) * stepX, h - pad - norm * usableH);
        }

        if (fill != null)
        {
            var geo = new StreamGeometry();
            using (var ctx = geo.Open())
            {
                ctx.BeginFigure(new Point(points[0].X, h), true, true);
                foreach (var point in points)
                    ctx.LineTo(point, true, false);
                ctx.LineTo(new Point(points[^1].X, h), true, false);
            }
            geo.Freeze();
            context.DrawGeometry(fill, null, geo);
        }

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(points[0], false, false);
            for (var i = 1; i < points.Length; i++)
                ctx.LineTo(points[i], true, false);
        }
        line.Freeze();

        context.DrawGeometry(null, new Pen(stroke, StrokeThickness)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round
        }, line);

        context.DrawEllipse(stroke, null, points[^1], 3.5, 3.5);
    }
}

/// <summary>
/// Paired columns per bucket — bytes in beside bytes out, for a month of days or
/// a year of months. Bars rather than a line because the buckets are totals over
/// discrete periods, not a continuously sampled signal.
/// </summary>
public sealed class BarPairChart : SeriesControl
{
    public static readonly DependencyProperty BucketsProperty =
        DependencyProperty.Register(nameof(Buckets), typeof(IEnumerable<TrafficBucket>), typeof(BarPairChart),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnBucketsChanged));

    public static readonly DependencyProperty InboundBrushProperty =
        DependencyProperty.Register(nameof(InboundBrush), typeof(Brush), typeof(BarPairChart),
            new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x4A, 0x9E, 0xFF)),
                FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty OutboundBrushProperty =
        DependencyProperty.Register(nameof(OutboundBrush), typeof(Brush), typeof(BarPairChart),
            new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x3B, 0xC8, 0xB4)),
                FrameworkPropertyMetadataOptions.AffectsRender));

    public IEnumerable<TrafficBucket>? Buckets
    {
        get => (IEnumerable<TrafficBucket>?)GetValue(BucketsProperty);
        set => SetValue(BucketsProperty, value);
    }

    public Brush? InboundBrush
    {
        get => (Brush?)GetValue(InboundBrushProperty);
        set => SetValue(InboundBrushProperty, value);
    }

    public Brush? OutboundBrush
    {
        get => (Brush?)GetValue(OutboundBrushProperty);
        set => SetValue(OutboundBrushProperty, value);
    }

    private static void OnBucketsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((BarPairChart)d).TrackSeries(BucketsProperty, e.NewValue);

    protected override void OnRender(DrawingContext context)
    {
        base.OnRender(context);

        var w = ActualWidth;
        var h = ActualHeight;
        if (w <= 1 || h <= 1) return;

        var buckets = Buckets?.ToList() ?? new List<TrafficBucket>();

        // Room under the plot for the x labels, and a left gutter for the scale.
        const double axisH = 16;
        const double gutter = 54;
        var plotH = Math.Max(10, h - axisH);
        var plotW = Math.Max(10, w - gutter);

        var muted = new SolidColorBrush(Color.FromArgb(150, 200, 220, 255));
        var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)), 1);

        for (var i = 0; i <= 4; i++)
        {
            var y = plotH * i / 4.0;
            context.DrawLine(gridPen, new Point(gutter, y), new Point(w, y));
        }

        if (buckets.Count == 0)
        {
            DrawPlaceholder(context, h, "No traffic recorded yet.");
            return;
        }

        var peak = buckets.Max(b => Math.Max(b.BytesIn, b.BytesOut));
        if (peak <= 0)
        {
            context.DrawText(Label("0 B", 10, muted), new Point(4, plotH - 12));
            DrawPlaceholder(context, plotH, "No traffic recorded in this period yet.");
            DrawAxisLabels(context, buckets, gutter, plotW, plotH, muted);
            return;
        }

        // Scale labels at the top and the midpoint — enough to read the chart
        // without turning the card into a spreadsheet.
        context.DrawText(Label(ByteSize.Format(peak), 10, muted), new Point(4, 0));
        context.DrawText(Label(ByteSize.Format(peak / 2.0), 10, muted), new Point(4, plotH / 2 - 6));

        var slot = plotW / buckets.Count;
        // Two bars plus breathing room, never thinner than a hairline on a
        // 31-day month in a narrow window.
        var barW = Math.Max(1.5, Math.Min(14, slot / 2 - 1.5));

        for (var i = 0; i < buckets.Count; i++)
        {
            var bucket = buckets[i];
            var centre = gutter + slot * (i + 0.5);
            DrawBar(context, centre - barW - 0.75, barW, bucket.BytesIn, peak, plotH, InboundBrush);
            DrawBar(context, centre + 0.75, barW, bucket.BytesOut, peak, plotH, OutboundBrush);
        }

        DrawAxisLabels(context, buckets, gutter, plotW, plotH, muted);
    }

    private static void DrawBar(DrawingContext context, double x, double width, long value,
        long peak, double plotH, Brush? brush)
    {
        if (value <= 0 || brush == null) return;
        // A day with traffic always shows something, even at 1/10000 of the peak.
        var barH = Math.Max(1.5, plotH * value / peak);
        context.DrawRoundedRectangle(brush, null, new Rect(x, plotH - barH, width, barH), 2, 2);
    }

    /// <summary>
    /// Thins the x labels until they fit: 31 day numbers in a half-width card
    /// overlap into a smear, so only every nth is drawn.
    /// </summary>
    private void DrawAxisLabels(DrawingContext context, List<TrafficBucket> buckets,
        double gutter, double plotW, double plotH, Brush brush)
    {
        var slot = plotW / buckets.Count;
        var every = Math.Max(1, (int)Math.Ceiling(26 / Math.Max(1, slot)));

        for (var i = 0; i < buckets.Count; i++)
        {
            if (i % every != 0 && i != buckets.Count - 1) continue;
            // Drop the second-to-last label when the final one would collide.
            if (i != buckets.Count - 1 && (buckets.Count - 1 - i) * slot < 22) continue;

            var text = Label(buckets[i].Label, 9, brush);
            var x = gutter + slot * (i + 0.5) - text.Width / 2;
            context.DrawText(text, new Point(x, plotH + 3));
        }
    }
}
