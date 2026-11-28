using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    internal enum BtnKind { Bar, BarOn, BarOff, BarDanger, Primary, Secondary, Ghost }

    /// <summary>A button drawn like the app's .tbtn / .btn (rounded, 1 px border, no focus rectangle).</summary>
    internal sealed class GcButton : Control
    {
        private bool _hover, _down;
        private BtnKind _kind;
        private string _icon;

        public Theme Theme = Theme.DarkTheme;
        public bool IconOnly;
        public int Pad = 10;
        public float FontPx = 12.5f;
        public int HeightPx = 30;

        public GcButton(string text, BtnKind kind, string icon = null)
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            SetStyle(ControlStyles.Selectable, false);
            Text = text; _kind = kind; _icon = icon;
            Cursor = Cursors.Hand;
            TabStop = false;
        }

        public BtnKind Kind { get => _kind; set { _kind = value; Invalidate(); } }
        public string Icon { get => _icon; set { _icon = value; Invalidate(); } }

        private int Dpi => DeviceDpi <= 0 ? 96 : DeviceDpi;
        private int S(float v) => (int)Math.Round(v * Dpi / 96f);

        public Size Measure()
        {
            int h = S(HeightPx);
            if (IconOnly) return new Size(h, h);
            var f = Fonts.Get("ui", FontPx, FontStyle.Bold, Dpi);
            int w = TextRenderer.MeasureText(Text ?? "", f, Size.Empty, TextFormatFlags.NoPadding).Width + S(Pad) * 2;
            if (_icon != null) w += S(15 + 6);
            return new Size(w, h);
        }

        public void Fit() { Size = Measure(); }

        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); Invalidate(); }
        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            var t = Theme;
            Color parentBg = Parent?.BackColor ?? t.Panel;
            g.Clear(parentBg);

            Color fill = Color.Empty, border = t.Line2, fg = t.Text;
            switch (_kind)
            {
                case BtnKind.BarOn: fill = t.AccBg; border = Color.Empty; fg = t.AccT; break;
                case BtnKind.BarOff: fg = t.Muted; break;
                case BtnKind.BarDanger: fg = t.Err; break;
                case BtnKind.Primary: fill = t.Acc; border = Color.Empty; fg = t.AccOn; break;
                case BtnKind.Secondary: fill = t.Panel2; break;
                case BtnKind.Ghost: border = Color.Empty; fg = t.Muted; break;
            }
            if (_hover && _kind != BtnKind.Primary && _kind != BtnKind.BarOn) fill = t.Panel2;
            if (_hover && _kind == BtnKind.Primary) fill = ControlPaint.Light(t.Acc, .15f);
            if (_down) fill = _kind == BtnKind.Primary ? ControlPaint.Dark(t.Acc, .05f) : t.Line;

            int r = S(_kind == BtnKind.Primary || _kind == BtnKind.Secondary || _kind == BtnKind.Ghost ? 10 : 8);
            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = Draw.Round(rect, r))
            {
                if (fill != Color.Empty) using (var b = new SolidBrush(fill)) g.FillPath(b, path);
                if (border != Color.Empty) using (var p = new Pen(border)) g.DrawPath(p, path);
            }

            int iconSize = S(15);
            if (IconOnly)
            {
                Icons.Paint(g, _icon, new Rectangle((Width - iconSize) / 2, (Height - iconSize) / 2, iconSize, iconSize), fg, Dpi);
                return;
            }
            var font = Fonts.Get("ui", FontPx, FontStyle.Bold, Dpi);
            int x = S(Pad);
            if (_icon != null)
            {
                Icons.Paint(g, _icon, new Rectangle(x, (Height - iconSize) / 2, iconSize, iconSize), fg, Dpi);
                x += iconSize + S(6);
            }
            TextRenderer.DrawText(g, Text, font, new Rectangle(x, 0, Width - x, Height), fg, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
        }
    }

    internal static class Draw
    {
        public static GraphicsPath Round(Rectangle r, int radius)
        {
            var p = new GraphicsPath();
            int d = Math.Max(1, Math.Min(radius * 2, Math.Min(r.Width, r.Height)));
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void Chip(Graphics g, string text, Rectangle at, Color fg, Color bg, int dpi, out int width)
        {
            var f = Fonts.Get("ui", 12f, FontStyle.Bold, dpi);
            int padX = 8 * dpi / 96;
            int w = TextRenderer.MeasureText(text, f, Size.Empty, TextFormatFlags.NoPadding).Width + padX * 2;
            int h = 22 * dpi / 96;
            var r = new Rectangle(at.X, at.Y + (at.Height - h) / 2, w, h);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Round(r, 6 * dpi / 96)) using (var b = new SolidBrush(bg)) g.FillPath(b, path);
            TextRenderer.DrawText(g, text, f, r, fg, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            width = w;
        }

        public static void Dot(Graphics g, Point center, int dpi, Color c)
        {
            int d = 9 * dpi / 96;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var b = new SolidBrush(c)) g.FillEllipse(b, center.X - d / 2, center.Y - d / 2, d, d);
        }

        /// <summary>Four bars of the connection quality (0..4 lit).</summary>
        public static int Quality(Graphics g, Point at, int level, int dpi, Color on, Color off)
        {
            int w = 3 * dpi / 96, gap = 2 * dpi / 96;
            int[] hs = { 4, 7, 10, 12 };
            for (int i = 0; i < 4; i++)
            {
                int h = hs[i] * dpi / 96;
                using (var b = new SolidBrush(i < level ? on : off))
                    g.FillRectangle(b, at.X + i * (w + gap), at.Y - h, w, h);
            }
            return 4 * (w + gap);
        }
    }

    /// <summary>The few line icons of the bar and the views (24-unit paths like the app's lucide icons).</summary>
    internal static class Icons
    {
        public static void Paint(Graphics g, string name, Rectangle r, Color c, int dpi)
        {
            if (string.IsNullOrEmpty(name)) return;
            var state = g.Save();
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TranslateTransform(r.X, r.Y);
            g.ScaleTransform(r.Width / 24f, r.Height / 24f);
            using (var pen = new Pen(c, 2f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                switch (name)
                {
                    case "fullscreen":
                        g.DrawLines(pen, new[] { P(8, 3), P(5, 3), P(3, 5), P(3, 8) });
                        g.DrawLines(pen, new[] { P(21, 8), P(21, 5), P(19, 3), P(16, 3) });
                        g.DrawLines(pen, new[] { P(3, 16), P(3, 19), P(5, 21), P(8, 21) });
                        g.DrawLines(pen, new[] { P(16, 21), P(19, 21), P(21, 19), P(21, 16) });
                        break;
                    case "clipboard":
                        using (var p = Draw.Round(new Rectangle(4, 4, 16, 18), 2)) g.DrawPath(pen, p);
                        using (var p = Draw.Round(new Rectangle(8, 2, 8, 4), 1)) g.DrawPath(pen, p);
                        break;
                    case "drive":
                        g.DrawLine(pen, 22, 12, 2, 12);
                        g.DrawLines(pen, new[] { P(5.45f, 5.11f), P(2, 12), P(2, 18), P(4, 20), P(20, 20), P(22, 18), P(22, 12), P(18.55f, 5.11f), P(16.76f, 4), P(7.24f, 4), P(5.45f, 5.11f) });
                        g.DrawLine(pen, 6, 16, 6.01f, 16);
                        g.DrawLine(pen, 10, 16, 10.01f, 16);
                        break;
                    case "pin":
                        g.DrawLine(pen, 12, 17, 12, 22);
                        g.DrawLines(pen, new[] { P(9, 10.76f), P(7.89f, 11.66f), P(5, 15.24f), P(5, 17), P(19, 17), P(19, 15.24f), P(16.11f, 11.66f), P(15, 10.76f), P(15, 7), P(16, 7), P(18, 5), P(18, 4), P(6, 4), P(6, 5), P(8, 7), P(9, 7), P(9, 10.76f) });
                        break;
                    case "minimize":
                        g.DrawLine(pen, 5, 12, 19, 12);
                        break;
                    case "monitor-x":
                        using (var p = Draw.Round(new Rectangle(2, 3, 20, 14), 2)) g.DrawPath(pen, p);
                        g.DrawLine(pen, 8, 21, 16, 21);
                        g.DrawLine(pen, 12, 17, 12, 21);
                        g.DrawLine(pen, 9.5f, 7.5f, 14.5f, 12.5f);
                        g.DrawLine(pen, 14.5f, 7.5f, 9.5f, 12.5f);
                        break;
                    case "check":
                        g.DrawLines(pen, new[] { P(20, 6), P(9, 17), P(4, 12) });
                        break;
                }
            }
            g.Restore(state);
        }

        private static PointF P(float x, float y) => new PointF(x, y);
    }
}
