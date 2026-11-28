using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace GateControl.RdpHost
{
    /// <summary>The app's colors (src/renderer/styles/app.css), dark and light.</summary>
    internal sealed class Theme
    {
        public bool Dark;
        public Color Bg, Panel, Panel2, Line, Line2, Text, Muted, Faint, Acc, AccOn, AccT, AccBg, Warn, WarnBg, Err, ErrBg, Info, InfoBg, Center;

        public static readonly Theme DarkTheme = new Theme
        {
            Dark = true,
            Bg = Hex("0D1015"), Panel = Hex("161B22"), Panel2 = Hex("1C222B"), Line = Hex("262D38"), Line2 = Hex("353E4B"),
            Text = Hex("E6EAF0"), Muted = Hex("A6AFBC"), Faint = Hex("8C96A5"),
            Acc = Hex("3DDC97"), AccOn = Hex("03261A"), AccT = Hex("46E0A0"), AccBg = Blend("3DDC97", "161B22", .12),
            Warn = Hex("F5B544"), WarnBg = Blend("F5B544", "161B22", .16), Err = Hex("FF8080"), ErrBg = Blend("FF8080", "161B22", .12),
            Info = Hex("79B8FF"), InfoBg = Blend("79B8FF", "161B22", .12), Center = Hex("0B0E13"),
        };

        public static readonly Theme LightTheme = new Theme
        {
            Dark = false,
            Bg = Hex("F3F5F8"), Panel = Hex("FFFFFF"), Panel2 = Hex("F4F6F9"), Line = Hex("DCE2EA"), Line2 = Hex("C4CCD8"),
            Text = Hex("0F1720"), Muted = Hex("465262"), Faint = Hex("566274"),
            Acc = Hex("0B8A5C"), AccOn = Hex("FFFFFF"), AccT = Hex("08724C"), AccBg = Blend("0B8A5C", "FFFFFF", .10),
            Warn = Hex("9A5B00"), WarnBg = Blend("D68A00", "FFFFFF", .13), Err = Hex("B42323"), ErrBg = Blend("C92A2A", "FFFFFF", .09),
            Info = Hex("1A56C4"), InfoBg = Blend("1D5FD1", "FFFFFF", .09), Center = Hex("E9EDF2"),
        };

        public static Theme Of(string name) => name == "light" ? LightTheme : DarkTheme;

        private static Color Hex(string h) => Color.FromArgb(Convert.ToInt32(h.Substring(0, 2), 16), Convert.ToInt32(h.Substring(2, 2), 16), Convert.ToInt32(h.Substring(4, 2), 16));

        private static Color Blend(string fg, string bg, double a)
        {
            Color f = Hex(fg), b = Hex(bg);
            return Color.FromArgb((int)(f.R * a + b.R * (1 - a)), (int)(f.G * a + b.G * (1 - a)), (int)(f.B * a + b.B * (1 - a)));
        }

        /// <summary>Dark / light title bar of the Windows frame (Windows 10 20H1+ and 11; older ones ignore it).</summary>
        public static void ApplyTitleBar(IntPtr hwnd, bool dark)
        {
            if (hwnd == IntPtr.Zero) return;
            int on = dark ? 1 : 0;
            try
            {
                if (DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int)) != 0) DwmSetWindowAttribute(hwnd, 19, ref on, sizeof(int));
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    }

    /// <summary>Fonts: Segoe UI Variable on Windows 11, Segoe UI elsewhere; Cascadia/Consolas for the numbers.</summary>
    internal static class Fonts
    {
        private static readonly HashSet<string> Installed = new HashSet<string>(FontFamily.Families.Select(f => f.Name), StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Font> Cache = new Dictionary<string, Font>();

        private static string Ui => Installed.Contains("Segoe UI Variable Text") ? "Segoe UI Variable Text" : "Segoe UI";
        private static string UiDisplay => Installed.Contains("Segoe UI Variable Display") ? "Segoe UI Variable Display" : "Segoe UI";
        private static string Mono => Installed.Contains("Cascadia Mono") ? "Cascadia Mono" : "Consolas";

        /// <summary>Size in pixels at 96 dpi, scaled to the window's dpi.</summary>
        public static Font Get(string kind, float px, FontStyle style, int dpi)
        {
            string family = kind == "mono" ? Mono : kind == "disp" ? UiDisplay : Ui;
            float size = px * dpi / 96f;
            string key = family + "|" + size.ToString("0.0") + "|" + (int)style;
            if (!Cache.TryGetValue(key, out var f))
            {
                f = new Font(family, size, style, GraphicsUnit.Pixel);
                Cache[key] = f;
            }
            return f;
        }
    }

    /// <summary>Texts of the window. The app sends its own (German or English) in connect.texts.</summary>
    internal static class Texts
    {
        private static readonly Dictionary<string, string> Defaults = new Dictionary<string, string>
        {
            ["title"] = "{0} – GateControl",
            ["connected"] = "Verbunden",
            ["connecting"] = "Verbinde …",
            ["loggingIn"] = "Anmeldung …",
            ["interrupted"] = "Unterbrochen",
            ["disconnected"] = "Getrennt",
            ["cancel"] = "Abbrechen",
            ["disconnect"] = "Trennen",
            ["clipboard"] = "Zwischenablage",
            ["clipboardPaused"] = "Zwischenablage pausiert",
            ["clipboardTip"] = "Zwischenablage teilen – ein Klick pausiert sie ohne Neuverbinden",
            ["drivesOn"] = "Laufwerke",
            ["drivesOff"] = "Laufwerke aus",
            ["drivesTip"] = "Laufwerke: Änderung gilt nach Neuverbinden",
            ["drivesAsk"] = "Die Freigabe der Laufwerke gilt erst nach einem Neuverbinden. Jetzt neu verbinden?",
            ["cad"] = "Strg+Alt+Entf",
            ["fullscreen"] = "Vollbild (Strg+Alt+Pause)",
            ["minimize"] = "Minimieren",
            ["window"] = "Fenster",
            ["windowTip"] = "Vollbild verlassen",
            ["pin"] = "Leiste anheften",
            ["fsHint"] = "Strg+Alt+Pause: zurück ins Fenster",
            ["q4"] = "Sehr gut", ["q3"] = "Gut", ["q2"] = "Mittel", ["q1"] = "Schwach", ["q0"] = "Schlecht",
            ["stepVpn"] = "VPN-Tunnel aktiv",
            ["stepReach"] = "Host erreichbar",
            ["stepCreds"] = "Anmeldedaten Ende-zu-Ende entschlüsselt",
            ["stepConnect"] = "Verbinde mit dem Remote-PC …",
            ["stepLogin"] = "Anmelden",
            ["memoryHint"] = "Die Anmeldedaten bleiben im Arbeitsspeicher dieser Sitzung. Es wird keine Datei und kein Eintrag im Windows-Anmeldeinformationsspeicher angelegt.",
            ["reconnecting"] = "Verbindung unterbrochen. Verbinde neu, Versuch {0} von {1} …",
            ["errLabel"] = "Verbindung getrennt",
            ["errTitle"] = "Die Verbindung wurde getrennt",
            ["errCode"] = "Grund {0} · erweiterter Code {1} · {2}",
            ["retry"] = "Erneut verbinden",
            ["mstsc"] = "Mit Windows-Remotedesktop öffnen",
            ["close"] = "Schließen",
            ["remoteDesktop"] = "Remotedesktop",
        };

        private static Dictionary<string, string> _app = new Dictionary<string, string>();

        public static void Use(Dictionary<string, object> fromApp)
        {
            var d = new Dictionary<string, string>();
            if (fromApp != null)
                foreach (var kv in fromApp)
                    if (kv.Value is string s && s.Length > 0 && s.Length < 600) d[kv.Key] = s;
            _app = d;
        }

        public static string T(string key, params object[] args)
        {
            string s = _app.TryGetValue(key, out var a) ? a : Defaults.TryGetValue(key, out var b) ? b : key;
            if (args == null || args.Length == 0) return s;
            try { return string.Format(s, args); } catch (FormatException) { return s; }
        }
    }
}
