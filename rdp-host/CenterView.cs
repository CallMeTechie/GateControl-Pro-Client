using System;
using System.Drawing;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    /// <summary>
    /// The middle of the window while there is no remote picture: the steps while connecting (design 3a)
    /// and the "Verbindung getrennt" card with its three buttons (design 4).
    /// </summary>
    internal sealed class CenterView : Control
    {
        public Theme Theme = Theme.DarkTheme;
        public bool ErrorMode;
        public string Address = "";
        public int StepActive = 3;   // 0 vpn, 1 reach, 2 creds, 3 connect, 4 login; > 4 all done
        public bool Gateway;          // gateway routes: no VPN step
        public string ErrTitle = "", ErrText = "", ErrCode = "";

        public readonly GcButton Retry, Mstsc, Close;
        private readonly Timer _spin = new Timer { Interval = 60 };
        private float _angle;

        public CenterView()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Dock = DockStyle.Fill;
            Retry = new GcButton(Texts.T("retry"), BtnKind.Primary) { HeightPx = 38, FontPx = 14f, Pad = 18 };
            Mstsc = new GcButton(Texts.T("mstsc"), BtnKind.Secondary) { HeightPx = 38, FontPx = 14f, Pad = 18 };
            Close = new GcButton(Texts.T("close"), BtnKind.Ghost) { HeightPx = 38, FontPx = 14f, Pad = 18 };
            Controls.Add(Retry); Controls.Add(Mstsc); Controls.Add(Close);
            _spin.Tick += (s, e) => { _angle = (_angle + 30) % 360; if (!ErrorMode && Visible) Invalidate(); };
            _spin.Start();
        }

        private int Dpi => DeviceDpi <= 0 ? 96 : DeviceDpi;
        private int S(float v) => (int)Math.Round(v * Dpi / 96f);

        public void Refresh2()
        {
            BackColor = Theme.Center;
            Retry.Text = Texts.T("retry"); Mstsc.Text = Texts.T("mstsc"); Close.Text = Texts.T("close");
            foreach (var b in new[] { Retry, Mstsc, Close }) { b.Theme = Theme; b.Fit(); b.Visible = ErrorMode; }
            LayoutCard();
            Invalidate(true);
        }

        protected override void OnResize(EventArgs e) { base.OnResize(e); LayoutCard(); }
        protected override void OnDpiChangedAfterParent(EventArgs e) { base.OnDpiChangedAfterParent(e); Refresh2(); }

        private Rectangle _card;
        private Rectangle _textRect;

        private void LayoutCard()
        {
            if (!ErrorMode) return;
            int w = Math.Min(S(620), Width - S(32));
            int pad = S(28);
            var body = Fonts.Get("ui", 15f, FontStyle.Regular, Dpi);
            int textH = TextRenderer.MeasureText(ErrText ?? "", body, new Size(w - pad * 2, int.MaxValue), TextFormatFlags.WordBreak | TextFormatFlags.NoPadding).Height;
            int h = pad + S(50) + S(16) + textH + S(14) + S(18) + S(18) + Retry.Height + pad;
            _card = new Rectangle((Width - w) / 2, Math.Max(S(16), (Height - h) / 2), w, h);
            _textRect = new Rectangle(_card.X + pad, _card.Y + pad + S(50) + S(16), w - pad * 2, textH);
            int by = _card.Bottom - pad - Retry.Height;
            Retry.Location = new Point(_card.X + pad, by);
            Mstsc.Location = new Point(Retry.Right + S(8), by);
            Close.Location = new Point(_card.Right - pad - Close.Width, by);
            if (Mstsc.Right > Close.Left - S(8)) Close.Location = new Point(Mstsc.Right + S(8), by); // narrow window
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var t = Theme;
            g.Clear(t.Center);
            if (ErrorMode) PaintError(g, t); else PaintSteps(g, t);
        }

        private void PaintSteps(Graphics g, Theme t)
        {
            var font = Fonts.Get("ui", 13.5f, FontStyle.Regular, Dpi);
            var small = Fonts.Get("ui", 12.5f, FontStyle.Regular, Dpi);
            var mono = Fonts.Get("mono", 12f, FontStyle.Regular, Dpi);
            string[] labels = { Texts.T("stepVpn"), Texts.T("stepReach"), Texts.T("stepCreds"), Texts.T("stepConnect"), Texts.T("stepLogin") };
            int w = Math.Min(S(480), Width - S(32));
            int rowH = S(32);
            int first = Gateway ? 1 : 0;
            int rows = labels.Length - first;
            int hintH = TextRenderer.MeasureText(Texts.T("memoryHint"), small, new Size(w, int.MaxValue), TextFormatFlags.WordBreak | TextFormatFlags.NoPadding).Height;
            int total = rows * rowH + S(14) + hintH;
            int x = (Width - w) / 2, y = (Height - total) / 2;
            for (int i = first; i < labels.Length; i++)
            {
                int ic = S(22);
                var icon = new Rectangle(x, y + (rowH - ic) / 2, ic, ic);
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                Color fg = t.Text;
                if (i < StepActive)
                {
                    using (var b = new SolidBrush(t.AccBg)) g.FillEllipse(b, icon);
                    Icons.Paint(g, "check", Rectangle.Inflate(icon, -S(5), -S(5)), t.AccT, Dpi);
                }
                else if (i == StepActive)
                {
                    using (var pen = new Pen(t.Info, S(2))) g.DrawArc(pen, Rectangle.Inflate(icon, -S(1), -S(1)), _angle, 270);
                }
                else
                {
                    using (var pen = new Pen(t.Line2, S(2))) g.DrawEllipse(pen, Rectangle.Inflate(icon, -S(1), -S(1)));
                    fg = t.Faint;
                }
                int tx = x + ic + S(10);
                string label = labels[i];
                int lw = TextRenderer.MeasureText(label, font, Size.Empty, TextFormatFlags.NoPadding).Width;
                TextRenderer.DrawText(g, label, font, new Rectangle(tx, y, lw + S(4), rowH), fg, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
                if (i == 1 && !string.IsNullOrEmpty(Address))
                    TextRenderer.DrawText(g, "· " + Address, mono, new Rectangle(tx + lw + S(6), y, S(260), rowH), t.Muted, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
                y += rowH;
            }
            y += S(14);
            TextRenderer.DrawText(g, Texts.T("memoryHint"), small, new Rectangle(x, y, w, hintH), t.Muted, TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
        }

        private void PaintError(Graphics g, Theme t)
        {
            if (_card.Width <= 0) LayoutCard();
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using (var path = Draw.Round(_card, S(14)))
            {
                using (var b = new SolidBrush(t.Panel)) g.FillPath(b, path);
                using (var p = new Pen(t.Line)) g.DrawPath(p, path);
            }
            int pad = S(28);
            var ic = new Rectangle(_card.X + pad, _card.Y + pad, S(44), S(44));
            using (var path = Draw.Round(ic, S(12))) using (var b = new SolidBrush(t.ErrBg)) g.FillPath(b, path);
            Icons.Paint(g, "monitor-x", Rectangle.Inflate(ic, -S(11), -S(11)), t.Err, Dpi);

            int tx = ic.Right + S(14);
            var lbl = Fonts.Get("ui", 12f, FontStyle.Bold, Dpi);
            var h = Fonts.Get("disp", 21f, FontStyle.Bold, Dpi);
            TextRenderer.DrawText(g, Texts.T("errLabel").ToUpperInvariant(), lbl, new Point(tx, ic.Y + S(1)), t.Faint, TextFormatFlags.NoPadding);
            TextRenderer.DrawText(g, ErrTitle ?? "", h, new Rectangle(tx, ic.Y + S(18), _card.Right - pad - tx, S(32)), t.Text, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);

            var body = Fonts.Get("ui", 15f, FontStyle.Regular, Dpi);
            TextRenderer.DrawText(g, ErrText ?? "", body, _textRect, t.Muted, TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
            var mono = Fonts.Get("mono", 12f, FontStyle.Regular, Dpi);
            TextRenderer.DrawText(g, ErrCode ?? "", mono, new Point(_textRect.X, _textRect.Bottom + S(14)), t.Faint, TextFormatFlags.NoPadding);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _spin.Dispose();
            base.Dispose(disposing);
        }
    }

    /// <summary>The amber banner while the control reconnects by itself (design 3b).</summary>
    internal sealed class ReconnectBanner : Control
    {
        public Theme Theme = Theme.DarkTheme;

        public ReconnectBanner()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        private int Dpi => DeviceDpi <= 0 ? 96 : DeviceDpi;

        public void Place(Control parent)
        {
            var f = Fonts.Get("ui", 12.5f, FontStyle.Regular, Dpi);
            int w = TextRenderer.MeasureText(Text ?? "", f, Size.Empty, TextFormatFlags.NoPadding).Width + 50 * Dpi / 96;
            int h = 34 * Dpi / 96;
            Bounds = new Rectangle((parent.ClientSize.Width - w) / 2, parent.ClientSize.Height > 0 ? 56 * Dpi / 96 : 0, w, h);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var t = Theme;
            g.Clear(Parent?.BackColor ?? t.Bg);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = Draw.Round(r, 10 * Dpi / 96))
            {
                using (var b = new SolidBrush(t.Panel)) g.FillPath(b, path);
                using (var b = new SolidBrush(t.WarnBg)) g.FillPath(b, path);
                using (var p = new Pen(Color.FromArgb(110, t.Warn))) g.DrawPath(p, path);
            }
            Draw.Dot(g, new Point(18 * Dpi / 96, Height / 2), Dpi, t.Warn);
            var f = Fonts.Get("ui", 12.5f, FontStyle.Regular, Dpi);
            TextRenderer.DrawText(g, Text, f, new Rectangle(32 * Dpi / 96, 0, Width, Height), t.Warn, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }
}
