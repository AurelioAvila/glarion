using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;

// Native Windows startup: no PowerShell execution-policy changes are needed.
static class LocalService
{
    const string Publisher = "4F8341A74D16077AE1849DC8B8CAC99F22606754";
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TrustFile { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Handle, Subject; }
    [StructLayout(LayoutKind.Sequential)]
    struct TrustData
    {
        public uint Size; public IntPtr Policy, Sip; public uint UI, Revocation, Choice;
        public IntPtr File; public uint StateAction; public IntPtr State, Url;
        public uint Flags, UIContext;
    }
    [DllImport("wintrust.dll", ExactSpelling = true)]
    static extern int WinVerifyTrust(IntPtr window, [In] ref Guid action, [In] ref TrustData data);

    static void VerifySignature(string path)
    {
        var file = new TrustFile { Size = (uint)Marshal.SizeOf(typeof(TrustFile)), Path = path };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFile)));
        try
        {
            Marshal.StructureToPtr(file, pointer, false);
            var data = new TrustData { Size = (uint)Marshal.SizeOf(typeof(TrustData)), UI = 2, Choice = 1, File = pointer, Flags = 0x80 };
            var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
            if (WinVerifyTrust(new IntPtr(-1), ref action, ref data) != 0)
                throw new InvalidOperationException("Invalid publisher signature: " + Path.GetFileName(path));
            using (var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                if (cert.Thumbprint != Publisher) throw new InvalidOperationException("Publisher mismatch");
        }
        finally { Marshal.DestroyStructure(pointer, typeof(TrustFile)); Marshal.FreeHGlobal(pointer); }
    }

    static void VerifyRelease(string root, string component)
    {
        var manifest = Path.Combine(root, "manifest.ps1");
        VerifySignature(manifest);
        var lines = File.ReadAllLines(manifest);
        var cms = new SignedCms();
        cms.Decode(Convert.FromBase64String(string.Concat(lines.SkipWhile(l => l != "# SIG # Begin signature block").Skip(1).TakeWhile(l => l != "# SIG # End signature block").Select(l => l.Substring(2).Trim()))));
        if (cms.SignerInfos.Count != 1 || !cms.SignerInfos[0].UnsignedAttributes.Cast<CryptographicAttributeObject>().Any(a => a.Oid.Value == "1.3.6.1.4.1.311.3.3.1" || a.Oid.Value == "1.2.840.113549.1.9.6"))
            throw new InvalidOperationException("A timestamped release manifest is required");
        var json = new JavaScriptSerializer();
        var files = json.Deserialize<Dictionary<string, string>>(lines.Single(l => l.StartsWith("# files=")).Substring(8));
        foreach (var required in new[] { component + ".exe", "local-service.exe", "nuclei.exe", "supabase-ca.crt" })
            if (!files.ContainsKey(required)) throw new InvalidOperationException("Missing critical release hash");
        foreach (var entry in files)
        {
            var path = Path.GetFullPath(Path.Combine(root, entry.Key));
            if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Invalid release path");
            using (var stream = File.OpenRead(path))
            using (var hash = SHA256.Create())
                if (BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "") != entry.Value) throw new InvalidOperationException("Changed release file: " + entry.Key);
        }
        VerifySignature(Path.Combine(root, component + ".exe"));
        VerifySignature(Path.Combine(root, "local-service.exe"));
    }

    static int Main(string[] args)
    {
        var root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        var logs = Path.GetFullPath(Path.Combine(root, "../logs"));
        try
        {
            if (args.Length < 1 || args.Length > 2 || (args[0] != "api" && args[0] != "runner") || (args.Length == 2 && args[1] != "--verify")) throw new ArgumentException("Choose api or runner, optionally --verify");
            var component = args[0];
            VerifyRelease(root, component);
            if (args.Length == 2 && args[1] == "--verify") return 0;
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(Path.GetFullPath(Path.Combine(root, "../private/settings.dpapi"))), null, DataProtectionScope.CurrentUser);
            Dictionary<string, string> settings;
            try { settings = new JavaScriptSerializer().Deserialize<Dictionary<string, string>>(System.Text.Encoding.UTF8.GetString(bytes)); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
            var start = new ProcessStartInfo(Path.Combine(root, component + ".exe")) { WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var setting in settings) start.EnvironmentVariables[setting.Key] = setting.Value;
            start.EnvironmentVariables.Remove("DATABASE_PASSWORD");
            start.EnvironmentVariables["PORT"] = "8187";
            start.EnvironmentVariables["DATABASE_MIGRATIONS"] = "verify";
            start.EnvironmentVariables["TRUST_PROXY_CLIENT_IP"] = "cloudflare";
            start.EnvironmentVariables["WEB_ROOT"] = Path.Combine(root, "web");
            start.EnvironmentVariables["PATH"] = root + ";" + start.EnvironmentVariables["PATH"];
            start.EnvironmentVariables["RUST_LOG"] = "info,sqlx=warn";
            Directory.CreateDirectory(logs);
            using (var output = new StreamWriter(Path.Combine(logs, component + ".stdout.log"), true) { AutoFlush = true })
            using (var error = new StreamWriter(Path.Combine(logs, component + ".stderr.log"), true) { AutoFlush = true })
            using (var process = new Process { StartInfo = start })
            {
                process.OutputDataReceived += (s, e) => { if (e.Data != null) output.WriteLine(e.Data); };
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) error.WriteLine(e.Data); };
                process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine(); process.WaitForExit();
                return process.ExitCode;
            }
        }
        catch (Exception error) { Directory.CreateDirectory(logs); File.AppendAllText(Path.Combine(logs, "startup.log"), DateTime.UtcNow.ToString("o") + " " + error.Message + Environment.NewLine); return 1; }
    }
}
