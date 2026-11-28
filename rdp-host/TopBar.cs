using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    internal enum Phase { Idle, Connecting, Connected, Reconnecting, Disconnected }

    /// <summary>What the bars show. One instance, shared by the window bar and the full-screen bar.</summary>
    internal sealed class SessionView
    {
        public string Name = "";
        public Phase Phase = Phase.Idle;
        public DateTime? Since;
        public int Quality = -1;      // 0..4 (mapped from the control's 0..7), -1 unknown
        public int RttMs = -1;
        public bool ClipboardAllowed, ClipboardOn, DrivesAllowed, DrivesOn;

        public static string Duration(DateTime? since)
        {
            if (since == null) return "";
            var d = DateTime.Now - since.Value;
            if (d < TimeSpan.Zero) d = TimeSpan.Zero;
            return string.Format("{0:00}:{1:00} h", (int)d.TotalHours, d.Minutes);
        }

        public string QualityText(bool withName)
        {
            if (Quality < 0) return RttMs >= 0 ? RttMs + " ms" : "";
            string q = Texts.T("q" + Quality);
            string rtt = RttMs >= 0 ? RttMs + " ms" : "";
            if (!withName) return rtt;
            return rtt.Length > 0 ? q + " · " + rtt : q;
        }
    }

    /// <summary>The 44 px bar below the Windows frame: status left, actions right (design picture 1).</summary>
    internal sealed class TopBar : Control
    {
        public Theme Theme = Theme.DarkTheme;
        public readonly SessionView View;
        private readonly List<GcButton> _right = new List<GcButton>();
        private readonly Timer _tick = new Timer { Interval = 1000 };

        public readonly GcButton Cancel, Clipboard, Drives, Cad, Full, Disconnect;
        public event Action CancelClicked, ClipboardClicked, DrivesClicked, CadClicked, FullClicked, DisconnectClicked;

        public TopBar(SessionView view)
        {
            View = view;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Dock = DockStyle.Top;
            Cancel = Add(Texts.T("cancel"), BtnKind.Bar, null, () => CancelClicked?.Invoke());
            Clipboard = Add(Texts.T("clipboard"), BtnKind.BarOn, "clipboard", () => ClipboardClicked?.Invoke());
            Drives = Add(Texts.T("drivesOff"), BtnKind.BarOff, "drive", () => DrivesClicked?.Invoke());
            Cad = Add(Texts.T("cad"), BtnKind.Bar, null, () => CadClicked?.Invoke());
            Full = Add("", BtnKind.Bar, "fullscreen", () => FullClicked?.Invoke());
            Full.IconOnly = true;
            Disconnect = Add(Texts.T("disconnect"), BtnKind.BarDanger, null, () => DisconnectClicked?.Invoke());
            _tick.Tick += (s, e) => { if (View.Phase == Phase.Connected) Invalidate(new Rectangle(0, 0, LeftWidth(), Height)); };
            _tick.Start();
        }

        private int Dpi => DeviceDpi <= 0 ? 96 : DeviceDpi;
        private int S(float v) => (int)Math.Round(v * Dpi / 96f);

        private GcButton Add(string text, BtnKind kind, string icon, Action click)
        {
            var b = new GcButton(text, kind, icon);
            b.Click += (s, e) => click();
            Controls.Add(b);
            _right.Add(b);
            return b;
        }

        public void SetTips(ToolTip tip)
        {
            tip.SetToolTip(Clipboard, Texts.T("clipboardTip"));
            tip.SetToolTip(Drives, Texts.T("drivesTip"));
            tip.SetToolTip(Full, Texts.T("fullscreen"));
        }

        /// <summary>Applies texts, theme and the phase: which buttons show, and their state.</summary>
        public void Refresh2()
        {
            BackColor = Theme.Panel;
            Height = S(44);
            var p = View.Phase;
            Cancel.Shown = p == Phase.Connecting || p == Phase.Idle;
            Clipboard.Shown = p == Phase.Connected && View.ClipboardAllowed;
            Drives.Shown = p == Phase.Connected && View.DrivesAllowed;
            Cad.Shown = p == Phase.Connected;
            Full.Shown = p == Phase.Connected;
            Disconnect.Shown = p == Phase.Connected || p == Phase.Reconnecting;

            Cancel.Text = Texts.T("cancel");
            Cad.Text = Texts.T("cad");
            Disconnect.Text = Texts.T("disconnect");
            Clipboard.Text = View.ClipboardOn ? Texts.T("clipboard") : Texts.T("clipboardPaused");
            Clipboard.Kind = View.ClipboardOn ? BtnKind.BarOn : BtnKind.BarOff;
            Drives.Text = View.DrivesOn ? Texts.T("drivesOn") : Texts.T("drivesOff");
            Drives.Kind = View.DrivesOn ? BtnKind.BarOn : BtnKind.BarOff;
            foreach (var b in _right) { b.Theme = Theme; b.Fit(); }
            LayoutButtons();
            Invalidate(true);
        }

        protected override void OnResize(EventArgs e) { base.OnResize(e); LayoutButtons(); }
        protected override void OnLayout(LayoutEventArgs e) { base.OnLayout(e); LayoutButtons(); }
        protected override void OnDpiChangedAfterParent(EventArgs e) { base.OnDpiChangedAfterParent(e); Refresh2(); }

        private void LayoutButtons()
        {
            if (Disconnect == null) return; // layout while the constructor adds the buttons
            int x = Width - S(10);
            int y = (Height - S(30)) / 2;
            // right to left: Trennen, Vollbild, Strg+Alt+Entf | Laufwerke, Zwischenablage, Abbrechen
            var order = new[] { Disconnect, Full, Cad, Drives, Clipboard, Cancel };
            foreach (var b in order)
            {
                if (!b.Shown) continue;
                if (b == Drives || (b == Clipboard && !Drives.Shown)) x -= S(17); // the separator between the groups
                x -= b.Width;
                b.Location = new Point(x, y);
                x -= S(8);
            }
            _sepX = Cad.Shown && (Clipboard.Shown || Drives.Shown) ? Cad.Left - S(12) : -1;
        }

        private int _sepX = -1;

        private int LeftWidth() => Width / 2;

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var t = Theme;
            g.Clear(t.Panel);
            using (var pen = new Pen(t.Line)) g.DrawLine(pen, 0, Height - 1, Width, Height - 1);
            if (_sepX > 0) using (var pen = new Pen(t.Line)) g.DrawLine(pen, _sepX, (Height - S(22)) / 2, _sepX, (Height + S(22)) / 2);

            int mid = Height / 2;
            int x = S(14);
            Color dot = View.Phase == Phase.Connected ? t.Acc : View.Phase == Phase.Disconnected ? t.Faint : t.Warn;
            Draw.Dot(g, new Point(x + S(4), mid), Dpi, dot);
            x += S(16);

            var nameFont = Fonts.Get("ui", 14f, FontStyle.Bold, Dpi);
            var name = View.Name ?? "";
            int nameW = TextRenderer.MeasureText(name, nameFont, Size.Empty, TextFormatFlags.NoPadding).Width;
            TextRenderer.DrawText(g, name, nameFont, new Rectangle(x, 0, nameW + S(4), Height), t.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
            x += nameW + S(10);

            string chip; Color cfg, cbg;
            switch (View.Phase)
            {
                case Phase.Connected: chip = Texts.T("connected"); cfg = t.AccT; cbg = t.AccBg; break;
                case Phase.Reconnecting: chip = Texts.T("interrupted"); cfg = t.Warn; cbg = t.WarnBg; break;
                case Phase.Disconnected: chip = Texts.T("disconnected"); cfg = t.Err; cbg = t.ErrBg; break;
                default: chip = Texts.T("connecting"); cfg = t.Info; cbg = t.InfoBg; break;
            }
            Draw.Chip(g, chip, new Rectangle(x, 0, 0, Height), cfg, cbg, Dpi, out int cw);
            x += cw + S(10);

            if (View.Phase != Phase.Connected) return;
            var mono = Fonts.Get("mono", 12f, FontStyle.Regular, Dpi);
            string dur = SessionView.Duration(View.Since);
            int dw = TextRenderer.MeasureText(dur, mono, Size.Empty, TextFormatFlags.NoPadding).Width;
            TextRenderer.DrawText(g, dur, mono, new Rectangle(x, 0, dw + S(4), Height), t.Muted, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            x += dw + S(12);
            string q = View.QualityText(true);
            if (q.Length == 0) return;
            using (var pen = new Pen(t.Line)) g.DrawLine(pen, x, mid - S(11), x, mid + S(11));
            x += S(12);
            if (View.Quality >= 0) x += Draw.Quality(g, new Point(x, mid + S(6)), View.Quality, Dpi, t.Acc, t.Line2) + S(6);
            TextRenderer.DrawText(g, q, mono, new Rectangle(x, 0, S(240), Height), t.Muted, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _tick.Dispose();
            base.Dispose(disposing);
        }
    }
}
