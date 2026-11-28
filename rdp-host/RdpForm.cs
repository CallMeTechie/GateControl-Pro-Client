using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    /// <summary>
    /// The session window: Windows frame, the GateControl bar, and below it the remote desktop of the RDP
    /// control — or, while there is none, the steps of connecting / the "Verbindung getrennt" card.
    /// </summary>
    internal sealed class RdpForm : Form
    {
        private readonly bool _demo;
        private readonly SessionView _view = new SessionView();
        private readonly TopBar _bar;
        private readonly Panel _content;
        private readonly CenterView _center;
        private readonly ReconnectBanner _banner;
        private readonly ToolTip _tip = new ToolTip();
        private readonly Timer _resizeDebounce = new Timer { Interval = 400 };
        private readonly Timer _edgeWatch = new Timer { Interval = 120 };
        private readonly List<Action> _pending = new List<Action>();
        private RdpEngine _engine;
        private FullscreenBar _fs;
        private Theme _theme = Theme.DarkTheme;
        private Rectangle _restoreBounds;
        private FormWindowState _restoreState;
        private bool _closing, _inFullScreen, _closedSent;
        private bool _startFullScreen;

        internal Control DemoSurface;

        public RdpForm(bool demo)
        {
            _demo = demo;
            Text = Texts.T("title", Texts.T("remoteDesktop"));
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.None;
            KeyPreview = false;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            _content = new Panel { Dock = DockStyle.Fill };
            _center = new CenterView();
            _banner = new ReconnectBanner { Visible = false };
            _bar = new TopBar(_view);
            _content.Controls.Add(_banner);
            _content.Controls.Add(_center);
            Controls.Add(_content);
            Controls.Add(_bar);

            _bar.CancelClicked += Disconnect;
            _bar.DisconnectClicked += Disconnect;
            _bar.CadClicked += () => _engine?.SendCtrlAltDel();
            _bar.FullClicked += () => SetFullScreen(true);
            _bar.ClipboardClicked += ToggleClipboard;
            _bar.DrivesClicked += ToggleDrives;
            _center.Retry.Click += (s, e) => RequestReconnect();
            _center.Mstsc.Click += (s, e) => Program.Send(new { type = "action", action = "mstsc" });
            _center.Close.Click += (s, e) => Close();

            _resizeDebounce.Tick += (s, e) => { _resizeDebounce.Stop(); PushDisplaySize(); };
            _content.Resize += (s, e) =>
            {
                _banner.Place(_content);
                if (_engine != null && _engine.LoggedIn) { _resizeDebounce.Stop(); _resizeDebounce.Start(); }
            };
            _edgeWatch.Tick += (s, e) => EdgeWatch();

            int dpi = DeviceDpi <= 0 ? 96 : DeviceDpi;
            var wa = Screen.PrimaryScreen.WorkingArea;
            Size = new Size(Math.Min(1280 * dpi / 96, wa.Width * 9 / 10), Math.Min(800 * dpi / 96, wa.Height * 9 / 10));
            MinimumSize = new Size(480 * dpi / 96, 320 * dpi / 96);
            ApplyTheme(_theme);
        }

        // ══ thread hand-over ═════════════════════════════════════════════════════
        /// <summary>Runs on the UI thread; queued until the window exists.</summary>
        public void Post(Action a)
        {
            lock (_pending)
            {
                if (!IsHandleCreated) { _pending.Add(a); return; }
            }
            try { BeginInvoke(a); } catch (InvalidOperationException) { }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Theme.ApplyTitleBar(Handle, _theme.Dark);
            Action[] queued;
            lock (_pending) { queued = _pending.ToArray(); _pending.Clear(); }
            foreach (var a in queued) BeginInvoke(a);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (_demo) return;
            Program.Send(new { type = "ready", pid = System.Diagnostics.Process.GetCurrentProcess().Id, version = Program.Version, mstscax = MstscaxVersion() });
        }

        private static string MstscaxVersion()
        {
            try { return System.Diagnostics.FileVersionInfo.GetVersionInfo(Environment.ExpandEnvironmentVariables(@"%WINDIR%\System32\mstscax.dll")).FileVersion; }
            catch { return null; }
        }

        // ══ messages of the app ══════════════════════════════════════════════════
        public void HandleMessage(Dictionary<string, object> m)
        {
            switch (J.Str(m, "type"))
            {
                case "connect": Connect(m); break;
                case "disconnect": _closing = true; Disconnect(); break;
                case "close": ShutdownFromParent(); break;
                case "fullscreen": SetFullScreen(J.Bool(m, "on", true)); break;
                case "cad": _engine?.SendCtrlAltDel(); break;
                case "clipboard": SetClipboard(J.Bool(m, "on", true)); break;
                case "focus": BringToFront2(); break;
                case "theme": ApplyTheme(Theme.Of(J.Str(m, "theme"))); break;
                case "explain":
                    if (_center.ErrorMode)
                    {
                        _center.ErrTitle = J.Str(m, "title") ?? _center.ErrTitle;
                        _center.ErrText = J.Str(m, "text") ?? _center.ErrText;
                        _center.Refresh2();
                    }
                    break;
            }
        }

        private void BringToFront2()
        {
            if (WindowState == FormWindowState.Minimized) WindowState = _restoreState == FormWindowState.Maximized ? FormWindowState.Maximized : FormWindowState.Normal;
            Activate();
            BringToFront();
            _engine?.Focus();
        }

        public void ShutdownFromParent()
        {
            _closing = true;
            if (_engine != null && _engine.IsConnected) _engine.Disconnect();
            else Close();
        }

        // ══ connect ══════════════════════════════════════════════════════════════
        private void Connect(Dictionary<string, object> m)
        {
            Texts.Use(J.Dict(m, "texts"));
            ApplyTheme(Theme.Of(J.Str(m, "theme")));
            _view.Name = J.Str(m, "name") ?? Texts.T("remoteDesktop");
            Text = Texts.T("title", _view.Name);
            var allow = J.Dict(m, "allow");
            var redirect = J.Dict(m, "redirect");
            _view.ClipboardAllowed = J.Bool(allow, "clipboard", false);
            _view.DrivesAllowed = J.Bool(allow, "drives", false);
            _view.ClipboardOn = _view.ClipboardAllowed && J.Bool(redirect, "clipboard", false);
            _view.DrivesOn = _view.DrivesAllowed && J.Bool(redirect, "drives", false);
            _view.Quality = -1; _view.RttMs = -1; _view.Since = null;
            _center.Address = J.Str(m, "address") ?? "";
            _center.Gateway = J.Bool(m, "gateway_route", false);
            _closing = false;
            ShowSteps(3);

            _engine?.Dispose();
            _engine = null;
            if (_demo) return;

            _engine = new RdpEngine(_content);
            _engine.Control.SendToBack(); // under the center view and the banner
            Wire(_engine);
            int dpi = DeviceDpi <= 0 ? 96 : DeviceDpi;
            var display = J.Dict(m, "display");
            string mode = J.Str(display, "mode");
            _startFullScreen = mode == "fullscreen";
            if (_startFullScreen) EnterFullScreenWindow(); // before connect: the remote desktop gets the screen's size
            _engine.Configure(m, dpi, _content.ClientSize, Log);
            m.Clear(); // nothing of the message stays around
            SetPhase(Phase.Connecting);
            Program.Send(new { type = "state", state = "connecting" });
            try { _engine.Connect(); }
            catch (Exception ex)
            {
                Program.Send(new { type = "error", code = ex.HResult, text = ex.Message });
                ShowError(0, 0, ex.Message);
            }
        }

        private void Wire(RdpEngine e)
        {
            e.State += s =>
            {
                Program.Send(new { type = "state", state = s });
                if (s == "connected") ShowSteps(4);
                if (s == "loggedin")
                {
                    _view.Since = _view.Since ?? DateTime.Now;
                    SetPhase(Phase.Connected);
                    _center.Visible = false;
                    if (_engine.Multimon) WindowState = FormWindowState.Minimized; // the control's own full screen spans the monitors
                    else if (_startFullScreen) _engine.FullScreen = true;
                    PushDisplaySize();
                    _engine.Focus();
                }
            };
            e.Reconnecting += (attempt, max) =>
            {
                Program.Send(new { type = "state", state = "reconnecting", attempt, max });
                SetPhase(Phase.Reconnecting);
                _banner.Text = Texts.T("reconnecting", attempt, max);
                _banner.Place(_content);
                _banner.Visible = true;
                _banner.BringToFront();
                _banner.Invalidate();
            };
            e.Reconnected += () =>
            {
                Program.Send(new { type = "state", state = "loggedin" });
                _banner.Visible = false;
                SetPhase(Phase.Connected);
            };
            e.Network += (q, rtt, bw) =>
            {
                Program.Send(new { type = "network", quality = q, rttMs = rtt, bandwidthKbps = bw });
                _view.Quality = q; _view.RttMs = rtt;
                _bar.Invalidate();
                if (_fs != null && _fs.Visible) _fs.Refresh2();
            };
            e.Warning += (kind, code) => Program.Send(new { type = "warning", kind, code });
            e.Disconnected += (reason, ext, text) =>
            {
                // 1 = disconnected here, 2 = by the user in the remote PC; ext 11/12 = disconnect / log-off by the user
                bool byUser = reason == 1 || reason == 2 || ext == 11 || ext == 12;
                Program.Send(new { type = "disconnected", reason, ext, text, byUser });
                if (_inFullScreen) LeaveFullScreenWindow();
                _banner.Visible = false;
                if (_reconnectAfterDisconnect)
                {
                    // "Laufwerke … jetzt neu verbinden": the window stays for the new connect
                    _reconnectAfterDisconnect = false;
                    ShowSteps(0);
                    Program.Send(new { type = "action", action = "reconnect" });
                    return;
                }
                if (_closing || byUser) { Close(); return; }
                ShowError(reason, ext, text);
            };
            e.RequestFullScreen += on => { if (on) EnterFullScreenWindow(); else LeaveFullScreenWindow(); };
            e.RequestMinimize += () => WindowState = FormWindowState.Minimized;
        }

        private void Log(string msg) => Program.Send(new { type = "log", level = "warn", msg });

        // ══ views ════════════════════════════════════════════════════════════════
        private void SetPhase(Phase p)
        {
            _view.Phase = p;
            _bar.Refresh2();
            if (_fs != null) _fs.Refresh2();
        }

        internal void ShowSteps(int active)
        {
            _center.ErrorMode = false;
            _center.StepActive = active;
            _center.Visible = true;
            _center.BringToFront();
            _center.Refresh2();
            if (_view.Phase != Phase.Connecting) SetPhase(Phase.Connecting);
        }

        internal void ShowError(int reason, int ext, string text)
        {
            _view.Since = null;
            _center.ErrorMode = true;
            _center.ErrTitle = Texts.T("errTitle");
            _center.ErrText = string.IsNullOrEmpty(text) ? "" : text;
            _center.ErrCode = Texts.T("errCode", reason, ext, DateTime.Now.ToString("HH:mm:ss"));
            _center.Visible = true;
            _center.BringToFront();
            _center.Refresh2();
            SetPhase(Phase.Disconnected);
        }

        /// <summary>"Erneut verbinden": the app fetches fresh credentials and sends connect again.</summary>
        private void RequestReconnect()
        {
            Program.Send(new { type = "action", action = "reconnect" });
            ShowSteps(0);
        }

        // ══ actions ══════════════════════════════════════════════════════════════
        private void Disconnect()
        {
            if (_engine != null && _engine.IsConnected) { _closing = true; _engine.Disconnect(); }
            else Close();
        }

        private void ToggleClipboard() => SetClipboard(!_view.ClipboardOn);

        private void SetClipboard(bool on)
        {
            if (!_view.ClipboardAllowed) return;
            if (_engine != null && !_engine.SetClipboard(on, Log)) return;
            _view.ClipboardOn = on;
            _bar.Refresh2();
            _fs?.Refresh2();
            Program.Send(new { type = "log", level = "info", msg = on ? "clipboard on" : "clipboard paused" });
        }

        private void ToggleDrives()
        {
            if (!_view.DrivesAllowed) return;
            bool want = !_view.DrivesOn;
            _view.DrivesOn = want;
            _bar.Refresh2();
            Program.Send(new { type = "setting", key = "drives", value = want });
            var answer = MessageBox.Show(this, Texts.T("drivesAsk"), Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (answer != DialogResult.Yes) return;
            _closing = false;
            if (_engine != null && _engine.IsConnected) { _reconnectAfterDisconnect = true; _engine.Disconnect(); }
            else RequestReconnect();
        }

        private bool _reconnectAfterDisconnect;

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_engine != null && _engine.IsConnected)
            {
                e.Cancel = true;
                _closing = true;
                _engine.Disconnect();
                return;
            }
            SendClosed();
            _fs?.Close();
            base.OnFormClosing(e);
        }

        private void SendClosed()
        {
            if (_closedSent) return;
            _closedSent = true;
            if (!_demo) Program.Send(new { type = "closed" });
        }

        // ══ full screen ══════════════════════════════════════════════════════════
        private void SetFullScreen(bool on)
        {
            if (_engine == null || _engine.Multimon) return;
            _engine.FullScreen = on; // raises OnRequestGo/LeaveFullScreen (ContainerHandledFullScreen = 1)
            if (on && !_inFullScreen) EnterFullScreenWindow();
            if (!on && _inFullScreen) LeaveFullScreenWindow();
        }

        internal void EnterFullScreenWindow()
        {
            if (_inFullScreen) return;
            _inFullScreen = true;
            _restoreState = WindowState;
            if (WindowState != FormWindowState.Normal) WindowState = FormWindowState.Normal;
            _restoreBounds = Bounds;
            _bar.Visible = false;
            FormBorderStyle = FormBorderStyle.None;
            Bounds = Screen.FromControl(this).Bounds;
            if (_fs == null)
            {
                _fs = new FullscreenBar(_view, ToggleClipboard, () => _engine?.SendCtrlAltDel(), () => WindowState = FormWindowState.Minimized, () => SetFullScreen(false), Disconnect)
                { Theme = _theme };
            }
            _fs.Refresh2();
            _fs.PlaceOn(Screen.FromControl(this));
            _fs.Intro();
            _fs.PlaceOn(Screen.FromControl(this));
            _edgeWatch.Start();
        }

        internal void LeaveFullScreenWindow()
        {
            if (!_inFullScreen) return;
            _inFullScreen = false;
            _edgeWatch.Stop();
            _fs?.Hide();
            FormBorderStyle = FormBorderStyle.Sizable;
            Bounds = _restoreBounds;
            if (_restoreState == FormWindowState.Maximized) WindowState = FormWindowState.Maximized;
            _bar.Visible = true;
            Theme.ApplyTitleBar(Handle, _theme.Dark);
        }

        private void EdgeWatch()
        {
            if (_fs == null || !_inFullScreen) return;
            if (WindowState == FormWindowState.Minimized || !ContainsFocusOrForeground()) { _fs.Reveal(false); return; }
            var scr = Screen.FromControl(this).Bounds;
            var p = Cursor.Position;
            bool atEdge = p.Y <= scr.Top + 2 && Math.Abs(p.X - (scr.Left + scr.Width / 2)) < Math.Max(_fs.Width / 2, 300);
            _fs.Reveal(atEdge || _fs.Bounds.Contains(p));
        }

        private bool ContainsFocusOrForeground() => Form.ActiveForm == this || Form.ActiveForm == _fs || GetForegroundWindow() == Handle;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        private void PushDisplaySize()
        {
            if (_engine == null) return;
            var size = _content.ClientSize;
            _engine.UpdateDisplay(size.Width, size.Height, DeviceDpi <= 0 ? 96 : DeviceDpi);
        }

        // ══ theme / dpi ══════════════════════════════════════════════════════════
        internal void ApplyTheme(Theme t)
        {
            _theme = t;
            BackColor = t.Bg;
            _content.BackColor = t.Center;
            _bar.Theme = t; _center.Theme = t; _banner.Theme = t;
            if (_fs != null) { _fs.Theme = t; _fs.Refresh2(); }
            _bar.Refresh2();
            _bar.SetTips(_tip);
            _center.Refresh2();
            if (DemoSurface != null) DemoSurface.Invalidate();
            if (IsHandleCreated) Theme.ApplyTitleBar(Handle, t.Dark);
        }

        protected override void OnDpiChanged(DpiChangedEventArgs e)
        {
            base.OnDpiChanged(e);
            _bar.Refresh2();
            _center.Refresh2();
            _fs?.Refresh2();
            _resizeDebounce.Stop(); _resizeDebounce.Start();
        }

        // ══ demo (screenshots in CI, no connection) ══════════════════════════════
        internal SessionView View => _view;
        internal TopBar Bar => _bar;
        internal CenterView Center => _center;
        internal ReconnectBanner Banner => _banner;
        internal Panel Content => _content;
        internal FullscreenBar Fs => _fs;
        internal void DemoPhase(Phase p) => SetPhase(p);

        internal void DemoFullScreen()
        {
            _inFullScreen = true;
            _bar.Visible = false;
            FormBorderStyle = FormBorderStyle.None;
            Bounds = Screen.FromControl(this).Bounds;
            _fs = new FullscreenBar(_view, () => { }, () => { }, () => { }, () => { }, () => { }) { Theme = _theme };
            _fs.Intro();
            _fs.PlaceOn(Screen.FromControl(this));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _engine?.Dispose();
                _resizeDebounce.Dispose(); _edgeWatch.Dispose(); _tip.Dispose();
                _fs?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
