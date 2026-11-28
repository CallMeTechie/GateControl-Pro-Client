using System;
using System.Drawing;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    /// <summary>
    /// The bar at the top in full screen (design picture 2): its own top-most window without a frame that
    /// never takes the focus from the session. Shown for 2 s when full screen starts, afterwards when the
    /// mouse reaches the top edge in the middle; the pin keeps it.
    /// </summary>
    internal sealed class FullscreenBar : Form
    {
        private static readonly Color Key = Color.FromArgb(255, 0, 254);
        private readonly SessionView _view;
        private readonly Timer _hide = new Timer { Interval = 2000 };
        private readonly Timer _hint = new Timer { Interval = 2500 };
        private bool _intro;
        public Theme Theme = Theme.DarkTheme;
        public bool Pinned { get; private set; }
        public bool HintVisible { get; private set; }

        public readonly GcButton Pin, Clipboard, Cad, Minimize, Window, Disconnect;

        public FullscreenBar(SessionView view, Action clipboard, Action cad, Action minimize, Action window, Action disconnect)
        {
            _view = view;
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            AutoScaleMode = AutoScaleMode.None;
            TransparencyKey = Key;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Pin = Add("", BtnKind.Bar, "pin", () => { Pinned = !Pinned; Refresh2(); if (!Pinned) _hide.Start(); });
            Pin.IconOnly = true;
            Clipboard = Add(Texts.T("clipboard"), BtnKind.BarOn, null, clipboard);
            Cad = Add(Texts.T("cad"), BtnKind.Bar, null, cad);
            Minimize = Add("", BtnKind.Bar, "minimize", minimize);
            Minimize.IconOnly = true;
            Window = Add(Texts.T("window"), BtnKind.Bar, null, window);
            Disconnect = Add(Texts.T("disconnect"), BtnKind.BarDanger, null, disconnect);
            _hide.Tick += (s, e) => { _hide.Stop(); _intro = false; };
            _hint.Tick += (s, e) => { _hint.Stop(); HintVisible = false; Invalidate(); };
        }

        protected override bool ShowWithoutActivation => true;

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x08000000 /* WS_EX_NOACTIVATE */ | 0x00000080 /* WS_EX_TOOLWINDOW */;
                return cp;
            }
        }

        private int Dpi => DeviceDpi <= 0 ? 96 : DeviceDpi;
        private int S(float v) => (int)Math.Round(v * Dpi / 96f);

        private GcButton Add(string text, BtnKind kind, string icon, Action click)
        {
            var b = new GcButton(text, kind, icon) { HeightPx = 28 };
            b.Click += (s, e) => click();
            Controls.Add(b);
            return b;
        }

        private int _textW;

        public void Refresh2()
        {
            BackColor = Theme.Panel;
            Clipboard.Visible = _view.ClipboardAllowed;
            Clipboard.Text = _view.ClipboardOn ? Texts.T("clipboard") : Texts.T("clipboardPaused");
            Clipboard.Kind = _view.ClipboardOn ? BtnKind.BarOn : BtnKind.BarOff;
            Pin.Kind = Pinned ? BtnKind.BarOn : BtnKind.Bar;
            Cad.Text = Texts.T("cad"); Window.Text = Texts.T("window"); Disconnect.Text = Texts.T("disconnect");
            foreach (Control c in Controls) if (c is GcButton b) { b.Theme = Theme; b.Fit(); }

            var nameFont = Fonts.Get("ui", 13f, FontStyle.Bold, Dpi);
            var mono = Fonts.Get("mono", 12f, FontStyle.Regular, Dpi);
            _textW = S(22) + TextRenderer.MeasureText(_view.Name ?? "", nameFont, Size.Empty, TextFormatFlags.NoPadding).Width + S(12)
                + S(26) + TextRenderer.MeasureText(_view.QualityText(false), mono, Size.Empty, TextFormatFlags.NoPadding).Width + S(14);

            int h = S(40);
            int x = S(6);
            Pin.Location = new Point(x, (h - Pin.Height) / 2);
            x = Pin.Right + _textW;
            foreach (var b in new[] { Clipboard, Cad, Minimize, Window, Disconnect })
            {
                if (!b.Visible) continue;
                b.Location = new Point(x, (h - b.Height) / 2);
                x = b.Right + S(6);
            }
            int barH = h + (HintVisible ? S(46) : 0);
            Size = new Size(x, barH);
            Region?.Dispose();
            Region = null;
            Invalidate(true);
        }

        public void PlaceOn(Screen s) => Location = new Point(s.Bounds.Left + (s.Bounds.Width - Width) / 2, s.Bounds.Top);

        /// <summary>Full screen started: visible for 2 s, with the hint below.</summary>
        public void Intro()
        {
            _intro = true;
            HintVisible = true;
            _hide.Stop(); _hide.Start();
            _hint.Stop(); _hint.Start();
            Refresh2();
            if (!Visible) Show();
        }

        /// <summary>Called by the edge watch of the window: show while the mouse is at the edge or on the bar.</summary>
        public void Reveal(bool show)
        {
            bool want = show || Pinned || _intro || HintVisible;
            if (want == Visible) return;
            if (want) Show(); else Hide();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var t = Theme;
            int h = S(40);
            g.Clear(t.Panel);
            using (var p = new Pen(t.Line2)) g.DrawRectangle(p, 0, -1, Width - 1, h);
            int x = Pin.Right + S(10);
            int mid = h / 2;
            Draw.Dot(g, new Point(x + S(4), mid), Dpi, _view.Phase == Phase.Connected ? t.Acc : t.Warn);
            x += S(14);
            var nameFont = Fonts.Get("ui", 13f, FontStyle.Bold, Dpi);
            string name = _view.Name ?? "";
            int nw = TextRenderer.MeasureText(name, nameFont, Size.Empty, TextFormatFlags.NoPadding).Width;
            TextRenderer.DrawText(g, name, nameFont, new Rectangle(x, 0, nw + S(4), h), t.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            x += nw + S(12);
            if (_view.Quality >= 0) x += Draw.Quality(g, new Point(x, mid + S(6)), _view.Quality, Dpi, t.Acc, t.Line2) + S(6);
            var mono = Fonts.Get("mono", 12f, FontStyle.Regular, Dpi);
            TextRenderer.DrawText(g, _view.QualityText(false), mono, new Rectangle(x, 0, S(80), h), t.Muted, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            using (var p = new Pen(t.Line)) g.DrawLine(p, Clipboard.Visible ? Clipboard.Left - S(8) : Cad.Left - S(8), mid - S(10), Clipboard.Visible ? Clipboard.Left - S(8) : Cad.Left - S(8), mid + S(10));

            if (HintVisible)
            {
                var hint = Texts.T("fsHint");
                var f = Fonts.Get("mono", 12f, FontStyle.Regular, Dpi);
                int hw = TextRenderer.MeasureText(hint, f, Size.Empty, TextFormatFlags.NoPadding).Width + S(24);
                var r = new Rectangle((Width - hw) / 2, h + S(12), hw, S(28));
                using (var b = new SolidBrush(Key)) g.FillRectangle(b, 0, h, Width, Height - h); // see-through below the bar
                using (var path = Draw.Round(r, S(9))) using (var b = new SolidBrush(Color.FromArgb(30, 30, 30))) g.FillPath(b, path);
                TextRenderer.DrawText(g, hint, f, r, Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { _hide.Dispose(); _hint.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
