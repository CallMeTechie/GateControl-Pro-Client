using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    /// <summary>
    /// --demo &lt;connecting|connected|reconnecting|error|fullscreen&gt; [--light] [--shot file.png]:
    /// the window in one of its views without the control and without a connection, with a painted
    /// stand-in for the remote desktop. For the screenshots of the CI run; names are made up.
    /// </summary>
    internal static class Demo
    {
        public static int Run(string view, bool light, string shot)
        {
            var form = new RdpForm(demo: true);
            var t = light ? Theme.LightTheme : Theme.DarkTheme;
            form.ApplyTheme(t);
            var v = form.View;
            v.Name = view == "error" ? "Labor-VM" : view == "connecting" ? "Werkstatt-Server" : "Buchhaltung-PC";
            form.Text = Texts.T("title", v.Name);
            v.ClipboardAllowed = true; v.ClipboardOn = !light;
            v.DrivesAllowed = true; v.DrivesOn = false;
            v.Quality = light ? 3 : 4; v.RttMs = light ? 38 : 14;
            v.Since = DateTime.Now.AddMinutes(light ? -4 : -72);
            form.Center.Address = "10.0.0.22:3389";

            var surface = new DesktopStandIn { Dock = DockStyle.Fill };
            form.DemoSurface = surface;
            form.Content.Controls.Add(surface);
            surface.SendToBack();

            switch (view)
            {
                case "connecting":
                    form.ShowSteps(3);
                    break;
                case "error":
                    form.ShowError(3, 5, "");
                    form.Center.ErrTitle = "Die Sitzung wurde vom Remote-PC beendet";
                    form.Center.ErrText = "Am Remote-PC hat sich jemand anderes angemeldet und deine Sitzung übernommen. Wenn du neu verbindest, wird die andere Person abgemeldet.";
                    form.Center.ErrCode = Texts.T("errCode", 3, 5, "10:41:07");
                    form.Center.Refresh2();
                    break;
                case "reconnecting":
                    form.Center.Visible = false;
                    form.DemoPhase(Phase.Reconnecting);
                    surface.Dim = true;
                    form.Banner.Text = Texts.T("reconnecting", 2, 20);
                    form.Banner.Visible = true;
                    form.Banner.BringToFront();
                    break;
                case "fullscreen":
                    form.Center.Visible = false;
                    form.DemoPhase(Phase.Connected);
                    form.StartPosition = FormStartPosition.Manual;
                    form.Location = new Point(40, 40);
                    form.Shown += (s, e) => form.DemoFullScreen();
                    break;
                default:
                    form.Center.Visible = false;
                    form.DemoPhase(Phase.Connected);
                    break;
            }
            form.Shown += (s, e) => form.Banner.Place(form.Content);

            if (shot != null)
            {
                var timer = new Timer { Interval = 1500 };
                timer.Tick += (s, e) =>
                {
                    timer.Stop();
                    try { Capture(form, shot); }
                    catch (Exception ex) { Console.Error.WriteLine("shot: " + ex.Message); }
                    form.Close();
                };
                form.Shown += (s, e) => timer.Start();
            }
            Application.Run(form);
            return 0;
        }

        /// <summary>The window as it is on the screen (with the frame and the full-screen bar).</summary>
        private static void Capture(RdpForm form, string file)
        {
            var b = VisibleBounds(form);
            using (var bmp = new Bitmap(b.Width, b.Height, PixelFormat.Format32bppArgb))
            {
                using (var g = Graphics.FromImage(bmp)) g.CopyFromScreen(b.Location, Point.Empty, b.Size);
                if (IsBlank(bmp))
                {
                    // no interactive desktop on the machine: draw the window itself
                    using (var g = Graphics.FromImage(bmp)) g.Clear(Color.Black);
                    form.DrawToBitmap(bmp, new Rectangle(Point.Empty, b.Size));
                    if (form.Fs != null && form.Fs.Visible)
                    {
                        using (var fb = new Bitmap(form.Fs.Width, form.Fs.Height))
                        {
                            form.Fs.DrawToBitmap(fb, new Rectangle(Point.Empty, fb.Size));
                            using (var g = Graphics.FromImage(bmp)) g.DrawImage(fb, form.Fs.Left - b.Left, form.Fs.Top - b.Top);
                        }
                    }
                }
                bmp.Save(file, ImageFormat.Png);
            }
        }

        [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
        private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT value, int size);

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        /// <summary>The window without its invisible resize border (DWMWA_EXTENDED_FRAME_BOUNDS).</summary>
        private static Rectangle VisibleBounds(Form form)
        {
            try
            {
                if (DwmGetWindowAttribute(form.Handle, 9, out RECT r, System.Runtime.InteropServices.Marshal.SizeOf(typeof(RECT))) == 0)
                    return Rectangle.FromLTRB(r.Left, r.Top, r.Right, r.Bottom);
            }
            catch (DllNotFoundException) { }
            return form.Bounds;
        }

        private static bool IsBlank(Bitmap bmp)
        {
            var first = bmp.GetPixel(bmp.Width / 2, bmp.Height / 2);
            for (int y = 0; y < bmp.Height; y += Math.Max(1, bmp.Height / 24))
                for (int x = 0; x < bmp.Width; x += Math.Max(1, bmp.Width / 24))
                    if (bmp.GetPixel(x, y) != first) return false;
            return true;
        }
    }

    /// <summary>A painted stand-in for the remote desktop (wallpaper, two windows, the taskbar).</summary>
    internal sealed class DesktopStandIn : Control
    {
        public bool Dim;

        public DesktopStandIn()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            int dpi = DeviceDpi <= 0 ? 96 : DeviceDpi;
            int S(int v) => v * dpi / 96;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var bg = new LinearGradientBrush(ClientRectangle, Color.FromArgb(0x2D, 0x5F, 0x9A), Color.FromArgb(0x08, 0x15, 0x2A), 120f))
                g.FillRectangle(bg, ClientRectangle);
            for (int i = 0; i < 3; i++)
                using (var b = new SolidBrush(Color.FromArgb(36, 255, 255, 255))) using (var p = Draw.Round(new Rectangle(S(18), S(18) + i * S(56), S(44), S(38)), S(6))) g.FillPath(b, p);
            Window(g, new Rectangle(S(150), S(70), S(540), S(330)), "Dokumente", Color.FromArgb(0xE8, 0xB4, 0x4A), dpi, true);
            Window(g, new Rectangle(S(560), S(230), S(460), S(260)), "Jahresplanung.xlsx", Color.FromArgb(0x21, 0xA3, 0x66), dpi, false);
            int th = S(44);
            using (var b = new SolidBrush(Color.FromArgb(220, 32, 32, 36))) g.FillRectangle(b, 0, Height - th, Width, th);
            for (int i = 0; i < 5; i++)
            {
                var c = i == 0 ? Color.FromArgb(0x2C, 0x9C, 0xE8) : Color.FromArgb(60, 255, 255, 255);
                using (var b = new SolidBrush(c)) using (var p = Draw.Round(new Rectangle(Width / 2 - S(80) + i * S(34), Height - th + S(9), S(26), S(26)), S(6))) g.FillPath(b, p);
            }
            var f = Fonts.Get("ui", 11f, FontStyle.Regular, dpi);
            TextRenderer.DrawText(g, "10:24\n27.11.2026", f, new Rectangle(Width - S(90), Height - th, S(80), th), Color.White, TextFormatFlags.Right | TextFormatFlags.VerticalCenter);
            if (Dim) using (var b = new SolidBrush(Color.FromArgb(110, 0, 0, 0))) g.FillRectangle(b, ClientRectangle);
        }

        private static void Window(Graphics g, Rectangle r, string title, Color mark, int dpi, bool rows)
        {
            int S(int v) => v * dpi / 96;
            using (var p = Draw.Round(r, S(8)))
            {
                using (var b = new SolidBrush(Color.FromArgb(0x20, 0x20, 0x20))) g.FillPath(b, p);
            }
            using (var b = new SolidBrush(Color.FromArgb(0x2B, 0x2B, 0x2B))) g.FillRectangle(b, r.X, r.Y + S(6), r.Width, S(28));
            using (var b = new SolidBrush(mark)) g.FillRectangle(b, r.X + S(12), r.Y + S(14), S(12), S(10));
            var f = Fonts.Get("ui", 12f, FontStyle.Regular, dpi);
            TextRenderer.DrawText(g, title, f, new Point(r.X + S(32), r.Y + S(11)), Color.FromArgb(0xED, 0xED, 0xED));
            if (!rows) return;
            string[] names = { "Name", "Angebote 2026", "Rechnungen", "Jahresplanung.xlsx", "Protokoll Teamrunde.docx" };
            for (int i = 0; i < names.Length; i++)
            {
                int y = r.Y + S(48) + i * S(30);
                TextRenderer.DrawText(g, names[i], f, new Point(r.X + S(18), y), i == 0 ? Color.FromArgb(0x9A, 0x9A, 0x9A) : Color.FromArgb(0xED, 0xED, 0xED));
                using (var p = new Pen(Color.FromArgb(0x2E, 0x2E, 0x2E))) g.DrawLine(p, r.X + S(14), y + S(24), r.Right - S(14), y + S(24));
            }
        }
    }
}
