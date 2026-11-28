using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows.Forms;
using AxMSTSCLib;
using MSTSCLib;

namespace GateControl.RdpHost
{
    /// <summary>
    /// IMsTscNonScriptable with the password as a raw BSTR, so our copy can be overwritten
    /// (Marshal.ZeroFreeBSTR) — .NET strings cannot be. First method after IUnknown: put_ClearTextPassword.
    /// </summary>
    [ComImport, Guid("C1E6743A-41C1-4A74-832A-0DD06C1C7A0E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IMsTscNonScriptableRaw
    {
        [PreserveSig] int put_ClearTextPassword(IntPtr bstr);
    }

    /// <summary>
    /// The Microsoft RDP control (mstscax.dll) and every setting the .rdp file of the mstsc way sets
    /// (src/services/rdp/rdp-config-builder.js), as COM properties. One instance per connect.
    /// </summary>
    internal sealed class RdpEngine : IDisposable
    {
        private readonly AxMsRdpClient9NotSafeForScripting _rdp;
        private string _fallbackServer;
        private bool _triedFallback, _loggedIn, _multimon, _fixed;

        public event Action<string> State;                         // connecting | connected | loggedin
        public event Action<int, int> Reconnecting;                // attempt, max
        public event Action Reconnected;
        public event Action<int, int, int> Network;                // quality 0..4 (-1), rtt ms, bandwidth kbps
        public event Action<int, int, string> Disconnected;        // reason, ext, text
        public event Action<string, int> Warning;                  // kind, code
        public event Action<bool> RequestFullScreen;
        public event Action RequestMinimize;

        public RdpEngine(Control parent)
        {
            _rdp = new AxMsRdpClient9NotSafeForScripting { Dock = DockStyle.Fill };
            ((System.ComponentModel.ISupportInitialize)_rdp).BeginInit();
            parent.Controls.Add(_rdp);
            ((System.ComponentModel.ISupportInitialize)_rdp).EndInit(); // creates the ActiveX control
            _rdp.CreateControl();
            Wire();
        }

        public Control Control => _rdp;
        public bool IsConnected { get { try { return _rdp.Connected != 0; } catch { return false; } } }
        public bool LoggedIn => _loggedIn;
        public bool Multimon => _multimon;

        public string Version { get { try { return _rdp.Version; } catch { return null; } } }

        private object Ocx => _rdp.GetOcx();

        /// <summary>Applies all settings of a connect message. Never logs the password.</summary>
        public void Configure(Dictionary<string, object> m, int dpi, System.Drawing.Size client, Action<string> log)
        {
            var adv = _rdp.AdvancedSettings9;
            var ns = (IMsRdpClientNonScriptable5)Ocx;
            var ext = (IMsRdpExtendedSettings)Ocx;

            // ── target (.rdp: full address / server port / alternate full address)
            _rdp.Server = J.Str(m, "server");
            _fallbackServer = J.Str(m, "fallbackServer");
            if (_fallbackServer == _rdp.Server) _fallbackServer = null;
            adv.RDPPort = J.Int(m, "port", 3389);

            // ── sign-in (.rdp: username / domain + cmdkey /generic:TERMSRV/…): only in this process' memory
            string user = J.Str(m, "username");
            if (!string.IsNullOrEmpty(user)) _rdp.UserName = user;
            string domain = J.Str(m, "domain");
            if (!string.IsNullOrEmpty(domain)) _rdp.Domain = domain;
            bool hasPassword = SetPassword(J.Str(m, "password"), log);
            m["password"] = null;

            ns.PromptForCredentials = J.Bool(m, "promptForCredentials", !hasPassword); // prompt for credentials:i:0
            ns.NegotiateSecurityLayer = true;                                           // negotiate security layer:i:1
            ns.AllowCredentialSaving = false;
            adv.EnableCredSspSupport = J.Bool(m, "nla", true);                          // enablecredsspsupport
            adv.AuthenticationLevel = 0;                                                // authentication level:i:0, this connection only

            // ── the new connection security dialog (CVE-2026-26151): embedded clients show it too (default 2).
            //    1 = the previous behaviour; then the old redirection dialog off as well. The redirections are
            //    the server's route plus the local restrictions — no .rdp file anybody could slip in.
            SetExt(ext, "RedirectionWarningDialogVersion", (uint)1, log);
            ns.ShowRedirectionWarningDialog = false;
            ns.WarnAboutSendingCredentials = false;
            ns.WarnAboutClipboardRedirection = false;

            // ── display
            var disp = J.Dict(m, "display");
            string mode = J.Str(disp, "mode") ?? "window";
            _multimon = mode == "multimon";
            _fixed = J.Str(disp, "resolution") == "fixed";
            uint scale = (uint)Math.Max(100, dpi * 100 / 96);
            SetExt(ext, "DesktopScaleFactor", scale, log);
            SetExt(ext, "DeviceScaleFactor", DeviceScale(scale), log);
            _rdp.ColorDepth = J.Int(disp, "colorDepth", 32);
            if (_multimon)
            {
                // all monitors: the control's own full screen like mstsc /multimon, with the Microsoft connection bar
                adv.ContainerHandledFullScreen = 0;
                ns.UseMultimon = true;
                ns.ConnectionBarText = J.Str(m, "name") ?? "";
                adv.DisplayConnectionBar = true;
                _rdp.FullScreen = true;
            }
            else
            {
                adv.ContainerHandledFullScreen = 1; // full screen is our window (our own bar)
                if (_fixed)
                {
                    _rdp.DesktopWidth = Clamp(J.Int(disp, "width", 1920), 200, 8192);
                    _rdp.DesktopHeight = Clamp(J.Int(disp, "height", 1080), 200, 8192);
                    adv.SmartSizing = true;
                }
                else
                {
                    _rdp.DesktopWidth = Clamp(client.Width, 200, 8192);
                    _rdp.DesktopHeight = Clamp(client.Height, 200, 8192);
                }
            }

            // ── keyboard: Win key, Alt+Tab … (0 here, 1 always remote, 2 only in full screen = mstsc's default)
            string kb = J.Str(m, "keyboard");
            _rdp.SecuredSettings3.KeyboardHookMode = kb == "always" ? 1 : kb == "never" ? 0 : 2;

            // ── redirections (.rdp: redirectclipboard/-drives/-printers/-smartcards, audiomode, audiocapturemode)
            var r = J.Dict(m, "redirect");
            adv.RedirectClipboard = J.Bool(r, "clipboard", false);
            adv.RedirectDrives = J.Bool(r, "drives", false);
            adv.RedirectPrinters = J.Bool(r, "printers", false);
            adv.RedirectSmartCards = J.Bool(r, "smartcards", false);
            string audio = J.Str(r, "audio");
            _rdp.SecuredSettings3.AudioRedirectionMode = audio == "remote" ? 1 : audio == "off" ? 2 : 0;
            adv.AudioCaptureRedirectionMode = false; // audiocapturemode:i:0, as the mstsc way

            // ── performance (.rdp: connection type / networkautodetect / bandwidthautodetect, visual effects)
            var perf = J.Dict(m, "performance");
            adv.NetworkConnectionType = (uint)Clamp(J.Int(perf, "connectionType", 7), 1, 7);
            adv.BandwidthDetection = J.Bool(perf, "bandwidthDetect", true);
            int flags = 0;
            if (J.Bool(perf, "disableWallpaper", false)) flags |= 0x1;
            if (J.Bool(perf, "disableThemes", false)) flags |= 0x8;
            if (J.Bool(perf, "disableAnimations", false)) flags |= 0x4 | 0x40;
            flags |= 0x80 | 0x100; // font smoothing, desktop composition (as mstsc on a LAN)
            adv.PerformanceFlags = flags;
            SetExt(ext, "EnableHardwareMode", true, log);
            adv.EnableAutoReconnect = true; // autoreconnection enabled:i:1
            adv.MaxReconnectAttempts = 20;

            // ── admin session (/admin) and start program (alternate shell)
            if (J.Bool(m, "admin", false)) adv.ConnectToAdministerServer = true;
            string start = J.Str(m, "startProgram");
            if (!string.IsNullOrEmpty(start)) _rdp.SecuredSettings3.StartProgram = start;

            // ── RD gateway (.rdp: gatewayhostname / gatewayusagemethod / …), its credentials in memory as well
            var gw = J.Dict(m, "gateway");
            string gwHost = J.Str(gw, "host");
            var ts = _rdp.TransportSettings4;
            if (!string.IsNullOrEmpty(gwHost))
            {
                ts.GatewayHostname = gwHost + ":" + J.Int(gw, "port", 443);
                ts.GatewayUsageMethod = 1;
                ts.GatewayProfileUsageMethod = 1;
                ts.GatewayCredsSource = 0;
                ts.GatewayCredSharing = 1;
            }
            else
            {
                ts.GatewayUsageMethod = 0;
            }
        }

        private static int Clamp(int v, int lo, int hi) => v < lo ? lo : v > hi ? hi : v;
        private static uint DeviceScale(uint scale) => scale >= 180 ? 180u : scale >= 140 ? 140u : 100u;

        /// <summary>The password as a BSTR that is zeroed right after the control took it.</summary>
        private bool SetPassword(string pw, Action<string> log)
        {
            if (string.IsNullOrEmpty(pw)) return false;
            IntPtr bstr = IntPtr.Zero;
            try
            {
                using (var ss = new SecureString())
                {
                    foreach (char c in pw) ss.AppendChar(c);
                    bstr = Marshal.SecureStringToBSTR(ss);
                }
                int hr = ((IMsTscNonScriptableRaw)Ocx).put_ClearTextPassword(bstr);
                if (hr == 0) return true;
                log("ClearTextPassword hr 0x" + hr.ToString("X8"));
            }
            catch (Exception ex) { log("ClearTextPassword raw: " + ex.GetType().Name); }
            finally { if (bstr != IntPtr.Zero) Marshal.ZeroFreeBSTR(bstr); }
            // fallback: the interop property (a managed copy, gone with the next GC)
            ((IMsTscNonScriptable)Ocx).ClearTextPassword = pw;
            return true;
        }

        /// <summary>IMsRdpExtendedSettings::Property; a failure is reported, never fatal.</summary>
        public static bool SetExt(IMsRdpExtendedSettings ext, string name, object value, Action<string> log)
        {
            try { ext.set_Property(name, ref value); return true; }
            catch (COMException ex) { log?.Invoke("ext " + name + ": 0x" + ex.HResult.ToString("X8")); return false; }
            catch (Exception ex) { log?.Invoke("ext " + name + ": " + ex.GetType().Name); return false; }
        }

        public void Connect() { _triedFallback = false; _rdp.Connect(); }

        public void Disconnect()
        {
            try { if (IsConnected) _rdp.Disconnect(); } catch (COMException) { }
        }

        public bool FullScreen
        {
            get { try { return _rdp.FullScreen; } catch { return false; } }
            set { try { _rdp.FullScreen = value; } catch (COMException) { } }
        }

        public void Focus() { try { _rdp.Focus(); } catch { } }

        /// <summary>Strg+Alt+Entf as scan codes: Ctrl 0x1D, Alt 0x38, Del 0x53 — down, then up.</summary>
        public void SendCtrlAltDel()
        {
            var ns = (IMsRdpClientNonScriptable)Ocx;
            int[] keys = { 0x1D, 0x38, 0x53, 0x53, 0x38, 0x1D };
            bool[] up = { false, false, false, true, true, true };
            _rdp.Focus();
            ns.SendKeys(keys.Length, ref up[0], ref keys[0]);
        }

        /// <summary>Pause / resume the shared clipboard during the session (no reconnect).</summary>
        public bool SetClipboard(bool on, Action<string> log) => SetExt((IMsRdpExtendedSettings)Ocx, "ManualClipboardSyncEnabled", !on, log);

        /// <summary>Dynamic resolution like "dynamic resolution:i:1" (IMsRdpClient9).</summary>
        public void UpdateDisplay(int width, int height, int dpi)
        {
            if (!_loggedIn || _multimon || _fixed || width < 200 || height < 200) return;
            uint scale = (uint)Math.Max(100, dpi * 100 / 96);
            try { _rdp.UpdateSessionDisplaySettings((uint)width, (uint)height, (uint)width, (uint)height, 0, scale, DeviceScale(scale)); }
            catch (COMException) { /* a server without the display control channel: the size stays */ }
            catch (ArgumentException) { }
        }

        private static int QualityOf(int rtt) => rtt < 0 ? -1 : rtt < 20 ? 4 : rtt < 60 ? 3 : rtt < 120 ? 2 : rtt < 250 ? 1 : 0;

        private void Wire()
        {
            _rdp.OnConnecting += (s, e) => State?.Invoke("connecting");
            _rdp.OnConnected += (s, e) => State?.Invoke("connected");
            _rdp.OnLoginComplete += (s, e) => { _loggedIn = true; State?.Invoke("loggedin"); };
            _rdp.OnAutoReconnecting2 += (s, e) => Reconnecting?.Invoke(e.attemptCount, e.maxAttemptCount);
            _rdp.OnAutoReconnected += (s, e) => Reconnected?.Invoke();
            _rdp.OnNetworkStatusChanged += (s, e) => Network?.Invoke(QualityOf(e.rtt), e.rtt, e.bandwidth);
            _rdp.OnWarning += (s, e) => Warning?.Invoke("warning", e.warningCode);
            _rdp.OnLogonError += (s, e) => Warning?.Invoke("logon", e.lError);
            _rdp.OnFatalError += (s, e) => Warning?.Invoke("fatal", e.errorCode);
            _rdp.OnDisconnected += (s, e) =>
            {
                _loggedIn = false;
                int ext = 0;
                try { ext = (int)_rdp.ExtendedDisconnectReason; } catch { }
                // 260: the name did not resolve -> once more with the IP (the .rdp file's "alternate full address")
                if (e.discReason == 260 && !_triedFallback && !string.IsNullOrEmpty(_fallbackServer))
                {
                    _triedFallback = true;
                    _rdp.Server = _fallbackServer;
                    try { _rdp.Connect(); return; } catch (COMException) { }
                }
                string text = null;
                try { text = _rdp.GetErrorDescription((uint)e.discReason, (uint)ext); } catch { }
                Disconnected?.Invoke(e.discReason, ext, text);
            };
            // container full screen: the control asks us to switch the window
            _rdp.OnRequestGoFullScreen += (s, e) => RequestFullScreen?.Invoke(true);
            _rdp.OnRequestLeaveFullScreen += (s, e) => RequestFullScreen?.Invoke(false);
            _rdp.OnRequestContainerMinimize += (s, e) => RequestMinimize?.Invoke();
            _rdp.OnConfirmClose += (s, e) => { e.pfAllowClose = true; };
        }

        public void Dispose()
        {
            try { Disconnect(); } catch { }
            try { _rdp.Parent?.Controls.Remove(_rdp); } catch { }
            try { _rdp.Dispose(); } catch { }
        }
    }

    /// <summary>Reading the JSON of JavaScriptSerializer (Dictionary / int / bool / string).</summary>
    internal static class J
    {
        public static Dictionary<string, object> Dict(Dictionary<string, object> m, string k) => m != null && m.TryGetValue(k, out var v) ? v as Dictionary<string, object> : null;
        public static string Str(Dictionary<string, object> m, string k) => m != null && m.TryGetValue(k, out var v) ? v as string : null;
        public static bool Bool(Dictionary<string, object> m, string k, bool d) => m != null && m.TryGetValue(k, out var v) && v is bool b ? b : d;
        public static int Int(Dictionary<string, object> m, string k, int d)
        {
            if (m == null || !m.TryGetValue(k, out var v) || v == null) return d;
            if (v is int i) return i;
            if (v is long l && l >= int.MinValue && l <= int.MaxValue) return (int)l;
            if (v is decimal dec) return (int)dec;
            return d;
        }
    }
}
