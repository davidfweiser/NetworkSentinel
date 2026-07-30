using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;

namespace NetworkSentinel.Controls;

public sealed class Sparkline : Control
{
    public static readonly StyledProperty<IEnumerable<double>?> ValuesProperty =
        AvaloniaProperty.Register<Sparkline, IEnumerable<double>?>(nameof(Values));

    public static readonly StyledProperty<IBrush?> StrokeProperty =
        AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(Stroke),
            new SolidColorBrush(Color.FromRgb(0x3D, 0xE7, 0xC8)));

    public static readonly StyledProperty<IBrush?> FillProperty =
        AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(Fill));

    public static readonly StyledProperty<double> StrokeThicknessProperty =
        AvaloniaProperty.Register<Sparkline, double>(nameof(StrokeThickness), 2.2);

    /// <summary>
    /// Per-sample threat counts, parallel to <see cref="Values"/>. Samples with a
    /// non-zero count get a vertical marker column, matching the web console's chart.
    /// </summary>
    public static readonly StyledProperty<IEnumerable<double>?> ThreatsProperty =
        AvaloniaProperty.Register<Sparkline, IEnumerable<double>?>(nameof(Threats));

    public static readonly StyledProperty<IBrush?> ThreatBrushProperty =
        AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(ThreatBrush),
            new SolidColorBrush(Color.FromArgb(77, 0xFF, 0x5D, 0x78)));

    private INotifyCollectionChanged? _subscribedValues;
    private INotifyCollectionChanged? _subscribedThreats;

    public IEnumerable<double>? Values
    {
        get => GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public IEnumerable<double>? Threats
    {
        get => GetValue(ThreatsProperty);
        set => SetValue(ThreatsProperty, value);
    }

    public IBrush? ThreatBrush
    {
        get => GetValue(ThreatBrushProperty);
        set => SetValue(ThreatBrushProperty, value);
    }

    public IBrush? Stroke
    {
        get => GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    public IBrush? Fill
    {
        get => GetValue(FillProperty);
        set => SetValue(FillProperty, value);
    }

    public double StrokeThickness
    {
        get => GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    static Sparkline()
    {
        AffectsRender<Sparkline>(ValuesProperty, StrokeProperty, FillProperty, StrokeThicknessProperty,
            ThreatsProperty, ThreatBrushProperty);
        ValuesProperty.Changed.AddClassHandler<Sparkline>((s, e) => s.OnValuesChanged(e));
        ThreatsProperty.Changed.AddClassHandler<Sparkline>((s, e) => s.OnThreatsChanged(e));
    }

    private void OnValuesChanged(AvaloniaPropertyChangedEventArgs e)
    {
        Resubscribe(ref _subscribedValues, e.NewValue);
    }

    private void OnThreatsChanged(AvaloniaPropertyChangedEventArgs e)
    {
        Resubscribe(ref _subscribedThreats, e.NewValue);
    }

    private void Resubscribe(ref INotifyCollectionChanged? slot, object? newValue)
    {
        if (slot != null)
            slot.CollectionChanged -= OnCollectionChanged;

        slot = newValue as INotifyCollectionChanged;
        if (slot != null)
            slot.CollectionChanged += OnCollectionChanged;

        InvalidateVisual();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.UIThread.Post(InvalidateVisual, DispatcherPriority.Render);
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);
        var values = Values?.ToList() ?? new List<double>();
        double w = Bounds.Width;
        double h = Bounds.Height;
        if (w <= 1 || h <= 1) return;

        var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)), 1);
        for (int i = 1; i < 4; i++)
        {
            double y = h * i / 4.0;
            context.DrawLine(gridPen, new Point(0, y), new Point(w, y));
        }

        if (values.Count < 2)
        {
            var muted = new FormattedText(
                "Collecting samples…",
                System.Globalization.CultureInfo.CurrentUICulture,
                FlowDirection.LeftToRight,
                new Typeface("Inter"),
                12,
                new SolidColorBrush(Color.FromArgb(140, 200, 220, 255)));
            context.DrawText(muted, new Point(12, h / 2 - 8));
            return;
        }

        // Zero-baseline scale, matching the web console's chart. Scaling to min..max
        // instead would stretch trivial noise into dramatic peaks.
        double max = Math.Max(1, values.Max());

        double pad = 6;
        double usableH = h - pad * 2;
        double stepX = w / (values.Count - 1);

        var points = new Point[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            double norm = values[i] / max;
            points[i] = new Point(i * stepX, h - pad - norm * usableH);
        }

        if (Fill != null)
        {
            var fillGeo = new StreamGeometry();
            using (var ctx = fillGeo.Open())
            {
                ctx.BeginFigure(new Point(points[0].X, h), true);
                ctx.LineTo(points[0]);
                for (int i = 1; i < points.Length; i++)
                    ctx.LineTo(points[i]);
                ctx.LineTo(new Point(points[^1].X, h));
                ctx.EndFigure(true);
            }
            context.DrawGeometry(Fill, null, fillGeo);
        }

        // Threat markers: a translucent column on each sample that carried an alert.
        // Drawn over the area fill but under the line, as the web chart does.
        var threats = Threats?.ToList();
        if (threats != null && ThreatBrush != null)
        {
            int marked = Math.Min(threats.Count, values.Count);
            for (int i = 0; i < marked; i++)
            {
                if (threats[i] <= 0) continue;
                context.DrawRectangle(ThreatBrush, null,
                    new RoundedRect(new Rect(i * stepX - 2, pad, 4, usableH), 2));
            }
        }

        var lineGeo = new StreamGeometry();
        using (var ctx = lineGeo.Open())
        {
            ctx.BeginFigure(points[0], false);
            for (int i = 1; i < points.Length; i++)
                ctx.LineTo(points[i]);
            ctx.EndFigure(false);
        }

        var pen = new Pen(Stroke, StrokeThickness)
        {
            LineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round
        };
        context.DrawGeometry(null, pen, lineGeo);

        var last = points[^1];
        context.DrawEllipse(Stroke, null, last, 4.5, 4.5);
        context.DrawEllipse(Brushes.White, null, last, 2.0, 2.0);
    }
}
