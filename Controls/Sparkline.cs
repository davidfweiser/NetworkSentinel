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

    private INotifyCollectionChanged? _subscribed;

    public IEnumerable<double>? Values
    {
        get => GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
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
        AffectsRender<Sparkline>(ValuesProperty, StrokeProperty, FillProperty, StrokeThicknessProperty);
        ValuesProperty.Changed.AddClassHandler<Sparkline>((s, e) => s.OnValuesChanged(e));
    }

    private void OnValuesChanged(AvaloniaPropertyChangedEventArgs e)
    {
        if (_subscribed != null)
            _subscribed.CollectionChanged -= OnCollectionChanged;

        _subscribed = e.NewValue as INotifyCollectionChanged;
        if (_subscribed != null)
            _subscribed.CollectionChanged += OnCollectionChanged;

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

        double min = values.Min();
        double max = values.Max();
        if (Math.Abs(max - min) < 0.001) { max = min + 1; min = Math.Max(0, min - 1); }

        double pad = 6;
        double usableH = h - pad * 2;
        double stepX = w / (values.Count - 1);

        var points = new Point[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            double norm = (values[i] - min) / (max - min);
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
