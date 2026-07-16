using System.Collections.Specialized;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace NetworkSentinel.Controls;

public sealed class Sparkline : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty =
        DependencyProperty.Register(nameof(Values), typeof(IEnumerable<double>), typeof(Sparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnValuesChanged));

    public static readonly DependencyProperty StrokeProperty =
        DependencyProperty.Register(nameof(Stroke), typeof(Brush), typeof(Sparkline),
            new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x3D, 0xE7, 0xC8)), FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty FillProperty =
        DependencyProperty.Register(nameof(Fill), typeof(Brush), typeof(Sparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeThicknessProperty =
        DependencyProperty.Register(nameof(StrokeThickness), typeof(double), typeof(Sparkline),
            new FrameworkPropertyMetadata(2.2, FrameworkPropertyMetadataOptions.AffectsRender));

    private INotifyCollectionChanged? _subscribed;

    public IEnumerable<double>? Values
    {
        get => (IEnumerable<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public Brush Stroke
    {
        get => (Brush)GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    public Brush? Fill
    {
        get => (Brush?)GetValue(FillProperty);
        set => SetValue(FillProperty, value);
    }

    public double StrokeThickness
    {
        get => (double)GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var spark = (Sparkline)d;
        if (spark._subscribed != null)
            spark._subscribed.CollectionChanged -= spark.OnCollectionChanged;

        spark._subscribed = e.NewValue as INotifyCollectionChanged;
        if (spark._subscribed != null)
            spark._subscribed.CollectionChanged += spark.OnCollectionChanged;

        spark.InvalidateVisual();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(InvalidateVisual, DispatcherPriority.Render);
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        var values = Values?.ToList() ?? new List<double>();
        double w = ActualWidth;
        double h = ActualHeight;
        if (w <= 1 || h <= 1) return;

        // Soft grid
        var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)), 1);
        for (int i = 1; i < 4; i++)
        {
            double y = h * i / 4.0;
            dc.DrawLine(gridPen, new Point(0, y), new Point(w, y));
        }

        if (values.Count < 2)
        {
            var muted = new FormattedText(
                "Collecting samples…",
                System.Globalization.CultureInfo.CurrentUICulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI"),
                12,
                new SolidColorBrush(Color.FromArgb(140, 200, 220, 255)),
                VisualTreeHelper.GetDpi(this).PixelsPerDip);
            dc.DrawText(muted, new Point(12, h / 2 - 8));
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

        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(points[0], Fill != null, false);
            for (int i = 1; i < points.Length; i++)
                ctx.LineTo(points[i], true, false);
        }
        geo.Freeze();

        if (Fill != null)
        {
            var fillGeo = new StreamGeometry();
            using (var ctx = fillGeo.Open())
            {
                ctx.BeginFigure(new Point(points[0].X, h), true, true);
                ctx.LineTo(points[0], true, false);
                for (int i = 1; i < points.Length; i++)
                    ctx.LineTo(points[i], true, false);
                ctx.LineTo(new Point(points[^1].X, h), true, false);
            }
            fillGeo.Freeze();
            dc.DrawGeometry(Fill, null, fillGeo);
        }

        var pen = new Pen(Stroke, StrokeThickness)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round
        };
        dc.DrawGeometry(null, pen, geo);

        // Glow endpoint
        var last = points[^1];
        dc.DrawEllipse(Stroke, null, last, 4.5, 4.5);
        dc.DrawEllipse(Brushes.White, null, last, 2.0, 2.0);
    }
}
