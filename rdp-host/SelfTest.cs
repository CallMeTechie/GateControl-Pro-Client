using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using MSTSCLib;

namespace GateControl.RdpHost
{
    /// <summary>
    /// --selftest (CI and the app's start check): creates the control in a hidden window, reads its version
    /// and sets what every connect sets before connecting — the dialog version, the redirection warning
    /// off, a password over the raw BSTR way — without any connection. One JSON line, exit code 0 / 1.
    /// </summary>
    internal static class SelfTest
    {
        public static int Run()
        {
            var checks = new Dictionary<string, object>();
            var notes = new List<string>();
            bool ok = false;
            string version = null;
            using (var form = new Form { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-32000, -32000), Size = new Size(320, 240), FormBorderStyle = FormBorderStyle.None, Opacity = 0 })
            {
                form.Shown += (s, e) =>
                {
                    try
                    {
                        using (var engine = new RdpEngine(form))
                        {
                            version = engine.Version;
                            checks["control"] = version != null;
                            var ocx = ((AxMSTSCLib.AxMsRdpClient9NotSafeForScripting)engine.Control).GetOcx();
                            var ext = (IMsRdpExtendedSettings)ocx;
                            checks["redirectionWarningDialogVersion"] = RdpEngine.SetExt(ext, "RedirectionWarningDialogVersion", (uint)1, n => notes.Add(n));
                            var ns = (IMsRdpClientNonScriptable5)ocx;
                            ns.ShowRedirectionWarningDialog = false;
                            checks["showRedirectionWarningDialog"] = true;
                            ns.PromptForCredentials = false;
                            ns.AllowCredentialSaving = false;
                            checks["nonScriptable5"] = true;
                            IntPtr bstr = System.Runtime.InteropServices.Marshal.StringToBSTR("selftest");
                            int hr;
                            try { hr = ((IMsTscNonScriptableRaw)ocx).put_ClearTextPassword(bstr); }
                            finally { System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(bstr); }
                            checks["clearTextPasswordRaw"] = hr == 0;
                            if (hr != 0) notes.Add("put_ClearTextPassword hr 0x" + hr.ToString("X8"));
                            ((IMsTscNonScriptable)ocx).ResetPassword();
                            // a full configure as for a connect (dummy target, no password), nothing is connected
                            var m = Program.Json.Deserialize<Dictionary<string, object>>(
                                "{\"name\":\"selftest\",\"server\":\"127.0.0.2\",\"fallbackServer\":\"127.0.0.3\",\"port\":3389,\"username\":\"selftest\",\"nla\":true," +
                                "\"display\":{\"mode\":\"window\",\"resolution\":\"dynamic\",\"colorDepth\":32},\"keyboard\":\"fullscreen\"," +
                                "\"redirect\":{\"clipboard\":true,\"drives\":false,\"printers\":false,\"smartcards\":false,\"audio\":\"local\"}," +
                                "\"performance\":{\"connectionType\":7,\"bandwidthDetect\":true},\"gateway\":{\"host\":\"gw.invalid\",\"port\":443}}");
                            engine.Configure(m, 96, new Size(1280, 800), n => notes.Add(n));
                            checks["configure"] = true;
                            ok = version != null && (bool)checks["clearTextPasswordRaw"];
                        }
                    }
                    catch (Exception ex)
                    {
                        notes.Add(ex.GetType().Name + ": " + ex.Message);
                    }
                    form.Close();
                };
                Application.Run(form);
            }
            Program.Send(new
            {
                type = "ready",
                selftest = true,
                ok,
                pid = System.Diagnostics.Process.GetCurrentProcess().Id,
                version = Program.Version,
                mstscax = version,
                checks,
                notes,
            });
            return ok ? 0 : 1;
        }
    }
}
