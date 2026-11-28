// gc-rdp-host.exe — one process per Remote Desktop session of the GateControl Pro client.
//
// Hosts the Microsoft RDP ActiveX control (mstscax.dll, the same engine as mstsc.exe) in its own window
// with the GateControl bar on top. Talks to the app over stdin/stdout, one JSON message per line (UTF-8).
// The channel belongs to the parent alone: no named pipe, no port. Credentials only ever arrive on stdin
// (never on the command line, which every process can read, never in a file or the Windows credential
// store).
//
//   App -> Host
//     connect     { name, address, server, fallbackServer, port, username, domain, password,
//                   promptForCredentials, nla, admin, startProgram,
//                   display { mode: window|fullscreen|multimon, resolution: dynamic|fixed, width, height, colorDepth },
//                   keyboard: fullscreen|always|never,
//                   redirect { clipboard, drives, printers, smartcards, audio: local|remote|off },
//                   allow { clipboard, drives }          (what the server permits; the bar offers no more)
//                   gateway { host, port } | null,
//                   performance { connectionType, bandwidthDetect, disableWallpaper, disableThemes, disableAnimations },
//                   theme: dark|light, texts { key: text } }
//                 Sent again on the same process for "Erneut verbinden".
//     disconnect  end the session (the window closes)
//     close       close the window (no error view)
//     focus       bring the window to the front
//     fullscreen  { on }
//     cad         Strg+Alt+Entf
//     clipboard   { on }  pause / resume the shared clipboard during the session
//     theme       { theme }
//     explain     { title, text }  the app's plain-language text for the last disconnect
//
//   Host -> App
//     ready        { pid, version, mstscax }
//     state        { state: connecting|connected|loggedin|reconnecting, attempt?, max? }
//     network      { quality, rttMs, bandwidthKbps }
//     warning      { code, kind? }
//     error        { code, text }
//     disconnected { reason, ext, text, byUser }
//     action       { action: reconnect|mstsc }   buttons of the error view
//     setting      { key: drives|clipboard, value }   changed in the bar (the app keeps it per host)
//     log          { level, msg }
//     closed
//
// End of stdin (app quit or crashed) => disconnect and exit: no session is left without its audit.
//
// Command line (no credentials):  --version | --selftest | --demo <view> [--light] [--shot <file.png>]
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    internal static class Program
    {
        private static readonly object OutLock = new object();
        private static TextWriter _out;
        internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1 << 20 };

        public static string Version => typeof(Program).Assembly.GetName().Version.ToString(3);

        [STAThread] // ActiveX needs an STA with a message loop
        private static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--version") { Console.Out.WriteLine(Version); Console.Out.Flush(); return 0; }

            _out = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (s, e) => Send(new { type = "error", code = -1, text = e.Exception.GetType().Name + ": " + e.Exception.Message });
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Send(new { type = "error", code = -2, text = (e.ExceptionObject as Exception)?.Message });

            if (args.Length == 1 && args[0] == "--selftest") return SelfTest.Run();

            int demoAt = Array.IndexOf(args, "--demo");
            if (demoAt >= 0)
            {
                string view = demoAt + 1 < args.Length ? args[demoAt + 1] : "connected";
                int shotAt = Array.IndexOf(args, "--shot");
                string shot = shotAt >= 0 && shotAt + 1 < args.Length ? args[shotAt + 1] : null;
                bool light = Array.IndexOf(args, "--light") >= 0;
                return Demo.Run(view, light, shot);
            }

            var form = new RdpForm(demo: false);
            StartStdinReader(form);
            Application.Run(form);
            return 0;
        }

        private static void StartStdinReader(RdpForm form)
        {
            var t = new Thread(() =>
            {
                var reader = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Length == 0) continue;
                    Dictionary<string, object> msg;
                    try { msg = Json.Deserialize<Dictionary<string, object>>(line); }
                    catch { Send(new { type = "log", level = "warn", msg = "invalid json" }); continue; }
                    line = null; // the line may hold the password
                    if (msg == null) continue;
                    form.Post(() => form.HandleMessage(msg));
                }
                // stdin closed: the app is gone -> disconnect cleanly and exit
                form.Post(form.ShutdownFromParent);
            }) { IsBackground = true, Name = "stdin" };
            t.Start();
        }

        public static void Send(object payload)
        {
            if (_out == null) return;
            string s = Json.Serialize(payload);
            lock (OutLock)
            {
                try { _out.WriteLine(s); } catch (IOException) { /* parent gone */ }
            }
        }
    }
}
