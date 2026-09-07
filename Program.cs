using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace HexiumLauncher
{

    internal static class HexiumTls
    {
        private static readonly X509Certificate2Collection? BundledRoots = LoadBundledRoots();

        private static X509Certificate2Collection? LoadBundledRoots()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var name = Array.Find(assembly.GetManifestResourceNames(),
                    n => n.EndsWith("cacert.pem", StringComparison.OrdinalIgnoreCase));
                if (name == null) return null;

                using var stream = assembly.GetManifestResourceStream(name);
                if (stream == null) return null;
                using var reader = new StreamReader(stream);
                var pem = reader.ReadToEnd();

                var roots = new X509Certificate2Collection();
                roots.ImportFromPem(pem);
                return roots.Count > 0 ? roots : null;
            }
            catch
            {

                return null;
            }
        }

        internal static int BundledRootCount => BundledRoots?.Count ?? 0;

        internal static bool Validate(
            object? sender,
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors errors)
        {

            if (errors == SslPolicyErrors.None) return true;

            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
            if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
            if (certificate == null) return false;
            if (BundledRoots == null) return false;

            try
            {
                using var leaf = new X509Certificate2(certificate);
                using var verify = new X509Chain();
                verify.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                verify.ChainPolicy.CustomTrustStore.AddRange(BundledRoots);
                verify.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                verify.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                if (chain != null)
                {
                    foreach (var element in chain.ChainElements)
                        verify.ChainPolicy.ExtraStore.Add(element.Certificate);
                }

                return verify.Build(leaf);
            }
            catch
            {
                return false;
            }
        }

        internal static string AdviceFor(Exception ex)
        {
            var text = string.Empty;
            for (var cur = ex; cur != null; cur = cur.InnerException)
                text += cur.GetType().Name + " " + cur.Message + " ";
            text = text.ToLowerInvariant();

            if (text.Contains("frame size") || text.Contains("corrupted frame")
                || text.Contains("unexpected end") || text.Contains("received an unexpected eof"))
            {
                return "Something between this PC and Hexium is interfering with the secure "
                     + "connection - the game server itself is fine.\n\n"
                     + "Try, in this order:\n"
                     + "  1. Turn off antivirus HTTPS / SSL / \"encrypted connection\" scanning\n"
                     + "  2. Disable any VPN, proxy or network filtering software\n"
                     + "  3. Test on a phone hotspot - if it works there, your network is blocking it";
            }

            if (text.Contains("remote certificate") || text.Contains("authenticationexception")
                || text.Contains("trust") || text.Contains("certificate is invalid"))
            {
                return "This PC cannot verify Hexium's certificate - the game server is fine.\n\n"
                     + "Run Windows Update to refresh its root certificates, and check whether "
                     + "antivirus HTTPS scanning is enabled.";
            }

            if (text.Contains("no such host") || text.Contains("name or service")
                || text.Contains("nameresolution"))
            {
                return "This PC could not look up hexium.zip. That is usually DNS filtering - "
                     + "try changing your DNS to 1.1.1.1 or 8.8.8.8, or test on a phone hotspot.";
            }

            if (text.Contains("timed out") || text.Contains("timeout"))
            {
                return "The connection timed out before Hexium answered. Check your internet "
                     + "connection, then try a phone hotspot to rule out your network.";
            }

            return "If this mentions a certificate or SSL, the game server is fine and the "
                 + "problem is on this PC or its network. Check antivirus HTTPS scanning, any "
                 + "VPN or proxy, and try a phone hotspot.";
        }

        internal static HttpClient CreateHttpClient(TimeSpan? timeout = null)
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    (message, cert, chain, errors) => Validate(message, cert, chain, errors)
            };
            var client = new HttpClient(handler);
            if (timeout.HasValue) client.Timeout = timeout.Value;
            return client;
        }
    }

    static class Program
    {

        internal static string DescribeException(Exception ex)
        {
            var sb = new System.Text.StringBuilder();
            var current = ex;
            var depth = 0;
            while (current != null && depth < 8)
            {
                sb.AppendLine($"{(depth == 0 ? "" : new string(' ', depth * 2) + "-> ")}{current.GetType().Name}: {current.Message}");
                if (current is System.Net.Sockets.SocketException socketEx)
                    sb.AppendLine($"{new string(' ', (depth + 1) * 2)}(socket error {socketEx.SocketErrorCode} / {socketEx.NativeErrorCode})");
                if (current is System.Security.Authentication.AuthenticationException)
                    sb.AppendLine($"{new string(' ', (depth + 1) * 2)}(certificate trust failure)");
                current = current.InnerException;
                depth++;
            }
            return sb.ToString().TrimEnd();
        }

        [STAThread]
        static void Main(string[] args)
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (TryApplyUpdate(args))
                return;

            string rawUrl = args.Length > 0 ? args[0] : "";
            var parsed = ParseUrl(rawUrl);
            Application.Run(new Launcher(parsed.placeId, parsed.ticket, parsed.year, parsed.jobId, rawUrl));
        }

        private static bool TryApplyUpdate(string[] args)
        {
            if (args.Length < 5 || !args[0].Equals("--apply-update", StringComparison.OrdinalIgnoreCase))
                return false;

            try
            {
                if (!int.TryParse(args[1], out int oldProcessId))
                    throw new InvalidDataException("The updater received an invalid process ID.");

                string targetPath = Path.GetFullPath(args[2]);
                string expectedTarget = Path.GetFullPath(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Hexium",
                    "HexiumLauncher.exe"));
                if (!targetPath.Equals(expectedTarget, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The updater target was not the Hexium installation path.");

                string expectedSha256 = args[3];
                string resumeUrl = args[4];
                string selfPath = Process.GetCurrentProcess().MainModule?.FileName
                    ?? throw new IOException("Could not locate the downloaded launcher update.");

                if (!Launcher.ComputeFileSha256(selfPath).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The downloaded launcher update failed its integrity check.");

                try
                {
                    using Process oldProcess = Process.GetProcessById(oldProcessId);
                    if (!oldProcess.WaitForExit(30000))
                        throw new TimeoutException("The previous launcher did not close in time.");
                }
                catch (ArgumentException)
                {

                }

                Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                File.Copy(selfPath, targetPath, overwrite: true);
                if (!Launcher.ComputeFileSha256(targetPath).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The installed launcher did not match the verified update.");

                var startInfo = new ProcessStartInfo
                {
                    FileName = targetPath,
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(targetPath)!
                };
                if (!string.IsNullOrWhiteSpace(resumeUrl))
                    startInfo.ArgumentList.Add(resumeUrl);
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Hexium Launcher could not finish updating.\n\n{DescribeException(ex)}",
                    "Hexium Launcher Update",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }

            return true;
        }

        public static (string placeId, string ticket, string year, string jobId) ParseUrl(string url)
        {
            string placeId = "", ticket = "", year = "2020", jobId = "";

            if (string.IsNullOrEmpty(url))
                return (placeId, ticket, year, jobId);

            try
            {
                string raw = url;
                if (raw.StartsWith("hexium://", StringComparison.OrdinalIgnoreCase))
                    raw = raw.Substring("hexium://".Length);
                else if (raw.StartsWith("bbclient://", StringComparison.OrdinalIgnoreCase))
                    raw = raw.Substring("bbclient://".Length);

                raw = Uri.UnescapeDataString(raw);

                if (raw.Contains("?") || raw.Contains("=") || raw.Contains("&"))
                {
                    int qIdx = raw.IndexOf('?');
                    string query = qIdx >= 0 ? raw.Substring(qIdx + 1) : raw;

                    var parts = query.Split('&');
                    foreach (var part in parts)
                    {
                        var kv = part.Split('=', 2);
                        if (kv.Length == 2)
                        {
                            string key = kv[0].Trim().ToLower();
                            string val = kv[1].Trim();
                            if (key == "place" || key == "placeid")
                                placeId = val;
                            else if (key == "ticket")
                                ticket = val;
                            else if (key == "year")
                                year = val;
                            else if (key == "jobid" || key == "gameid" || key == "guid")
                                jobId = val;
                        }
                    }
                }
                else
                {
                    var parts = raw.Split('+', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0) placeId = parts[0].Trim();
                    if (parts.Length > 1) ticket = parts[1].Trim();
                    if (parts.Length > 2) year = parts[2].Trim();
                    if (parts.Length > 3) jobId = parts[3].Trim();
                }
            }
            catch { }

            return (placeId, ticket, year, jobId);
        }
    }

    public partial class Launcher : Form
    {
        private readonly string placeId;
        private readonly string ticket;
        private readonly string year;
        private readonly string jobId;
        private readonly string rawUrl;

        private readonly string clientlocation;
        private readonly string cfgpath;
        private readonly string launcherpath;

        private bool Installing = false;
        private bool FirstRun = false;
        private bool NeedsRegistration = false;

        private ProgressBar progress = null!;
        private Label status = null!;
        private Button cancelBtn = null!;

        private string ClientDir = null!;
        private string ClientZIP = null!;
        private string ClientExe = null!;
        private string DownloadUrl = null!;
        private string ClientArchiveSha256 = null!;
        private string ClientExecutableSha256 = null!;
        private string ClientVersion = null!;
        private string ClientDisplayName = null!;
        private bool IsDevClient = false;

        private const string LauncherVersion = "2.1.44";
        private const string LegacyPolicyResponseJson =
            "{\"isSubjectToChinaPolicies\":false,\"arePaidRandomItemsRestricted\":false," +
            "\"isPaidItemTradingAllowed\":true,\"allowedExternalLinkReferences\":[]}";
        private const string UpdateManifestUrl = "https://hexium.zip/downloads/launcher-manifest.json";

        private const string VoiceHelperUrl = "https://hexium.zip/downloads/HexiumVoice.exe?v=8bead9a4a7224d93";
        private const string VoiceHelperSha256 = "8bead9a4a7224d937c4cb6254d436e36e5044fda115423892778bd70fe7f54df";
        private const string Protocol = "hexium";
        private const string LegacyProtocol = "bbclient";
        private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Hexium";
        private const long MaximumLauncherDownloadBytes = 300L * 1024L * 1024L;

        private const string SiteBaseUrl = "https://hexium.zip";

        private const string ClientSettingsBaseUrl = "https://www.hexium.zip";
        private static readonly string ExpectedClientAppSettings =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
            "<Settings>\r\n" +
            "\t<ContentFolder>content</ContentFolder>\r\n" +
            $"\t<BaseUrl>{ClientSettingsBaseUrl}/</BaseUrl>\r\n" +
            "</Settings>\r\n";

        private sealed class LauncherUpdateManifest
        {
            public string Version { get; set; } = "";
            public string Url { get; set; } = "";
            public string Sha256 { get; set; } = "";
            public long Size { get; set; }
        }

        public Launcher(string placeId, string ticket, string year, string jobId, string rawUrl)
        {
            this.placeId = placeId;
            this.ticket = ticket;
            this.rawUrl = rawUrl;
            this.jobId = jobId;

            this.year = DeterminePlaceYear(placeId);

            clientlocation = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Hexium");
            cfgpath = Path.Combine(clientlocation, "launcher.cfg");
            launcherpath = Path.Combine(clientlocation, "HexiumLauncher.exe");

            ConfigureClientProfile(false);

            IsFirstRun();
            CheckProtocolRegistration();
            CleanupOldUpdates();
            Init();

            Shown += (s, e) => Start();
        }

        private string DeterminePlaceYear(string placeIdValue)
        {
            try
            {
                if (long.TryParse(placeIdValue, out long pid) && pid > 0)
                {
                    using var http = HexiumTls.CreateHttpClient(TimeSpan.FromSeconds(6));
                    http.DefaultRequestHeaders.Add("User-Agent", "HexiumLauncher/" + LauncherVersion);
                    string json = http.GetStringAsync($"{SiteBaseUrl}/api/place-year?placeId={pid}").GetAwaiter().GetResult();
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("year", out var yp) && yp.GetInt32() == 2021)
                    {
                        WriteLog($"Place {pid} is year 2021; using the 2021 client.");
                        return "2021";
                    }
                }
            }
            catch (Exception ex) { WriteLog($"place-year lookup failed, defaulting to 2020: {ex.Message}"); }
            return "2020";
        }
        private void ConfigureClientProfile(bool isDev)
        {
            IsDevClient = isDev;
            if (isDev)
            {
                ClientDir = Path.Combine(clientlocation, "DevClient2020");
                ClientZIP = Path.Combine(clientlocation, "DevClient2020.zip");
                ClientExe = Path.Combine(ClientDir, "DevHexiumPlayerBeta.exe");
                DownloadUrl = "https://hexium.zip/downloads/DevClient2020.zip?v=6b9e5de7cefa296d";
                ClientArchiveSha256 = "6b9e5de7cefa296d5892e0940be96944bbbec0329f5f1a5455ffe3299aa9590a";
                ClientExecutableSha256 = "82b306892afcc25fb6a27b1fc0208fe25b72b6dfbaab928a19151660eb5e5a47";

                ClientVersion = "2020L-dev-hexium-v3";
                ClientDisplayName = "Hexium 2020 Dev Client";
            }
            else if (this.year == "2021")
            {
                ClientDir = Path.Combine(clientlocation, "HexiumPlayer2021");
                ClientZIP = Path.Combine(clientlocation, "HexiumPlayer2021.zip");
                ClientExe = Path.Combine(ClientDir, "HexiumPlayer2021.exe");
                DownloadUrl = "https://hexium.zip/downloads/HexiumPlayer2021.zip?v=ad60da83422dae04";
                ClientArchiveSha256 = "ad60da83422dae041545a2ad8b897ef38b5848fd2d2240afc57e95e357309dcd";
                ClientExecutableSha256 = "905a88282fdde9b1ff69f60312bcefe095f1301cfd275035f8bdb9527084795d";
                ClientVersion = "2021M-hexium-v1";
                ClientDisplayName = "Hexium 2021 Client";
            }
            else
            {
                ClientDir = Path.Combine(clientlocation, "HexiumPlayer");
                ClientZIP = Path.Combine(clientlocation, "HexiumPlayer.zip");
                ClientExe = Path.Combine(ClientDir, "HexiumPlayer.exe");
                DownloadUrl = "https://hexium.zip/downloads/HexiumPlayer.zip?v=d1a7c02cc0fa2de8";
                ClientArchiveSha256 = "d1a7c02cc0fa2de8e4a624f965a03879ba17873dd5e219908822a07aca15a388";
                ClientExecutableSha256 = "B26FF166F6D1F3287DF9B5FD10466FD7C7DFBA0FD276574EBF28942DB87E9220";

                ClientVersion = "2020L-hexium-projectx-v8";
                ClientDisplayName = "Hexium 2020 Client";
            }
        }

        private async Task<bool> CheckDevClientModeAsync()
        {
            try
            {
                using var http = HexiumTls.CreateHttpClient(TimeSpan.FromSeconds(5));
                http.DefaultRequestHeaders.Add("User-Agent", "HexiumLauncher/" + LauncherVersion);
                string json = await http.GetStringAsync($"{SiteBaseUrl}/api/dev-client-mode/status");
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("enabled", out var prop))
                {
                    bool enabled = prop.GetBoolean();
                    WriteLog($"Dev Client Mode check returned: {enabled}");
                    return enabled;
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Dev Client Mode check failed (defaulting to standard): {ex.Message}");
            }
            return false;
        }

        private void WriteLog(string message)
        {
            try
            {
                string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
                string logContent = $"[{timestamp}] {message}\r\n";

                string logFile = Path.Combine(clientlocation, "launcher.log");
                File.AppendAllText(logFile, logContent);

                string localLogFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "launcher.log");
                if (localLogFile != logFile)
                {
                    File.AppendAllText(localLogFile, logContent);
                }
            }
            catch { }
        }

        private void WriteLastLaunch(string placeId, string year)
        {
            try
            {
                string content = $"UTC={DateTime.UtcNow.ToString("o")}\r\n" +
                                 $"LauncherVersion={LauncherVersion}\r\n" +
                                 $"ClientVersion={ClientVersion}\r\n" +
                                 $"PlaceId={placeId}\r\n" +
                                 $"TicketPresent={!string.IsNullOrEmpty(ticket)}\r\n" +
                                 $"Year={year}\r\n" +
                                 $"ClientPath={ClientExe}\r\n" +
                                 $"ClientSha256={ComputeFileSha256(ClientExe)}\r\n" +
                                 $"AppSettingsPath={Path.Combine(ClientDir, "AppSettings.xml")}\r\n" +
                                 $"AppSettingsSha256={ComputeFileSha256(Path.Combine(ClientDir, "AppSettings.xml"))}\r\n" +
                                 $"ContentPath={Path.Combine(ClientDir, "content")}\r\n" +
                                 $"AuthUrl={SiteBaseUrl}/Login/Negotiate.ashx\r\n" +
                                 $"PlaceLauncherUrl={SiteBaseUrl}/game/PlaceLauncher.ashx?placeid={placeId}&{year}=true\r\n";

                string lastLaunchPath = Path.Combine(clientlocation, "last-launch.txt");
                File.WriteAllText(lastLaunchPath, content);

                string localLastLaunchPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "last-launch.txt");
                if (localLastLaunchPath != lastLaunchPath)
                {
                    File.WriteAllText(localLastLaunchPath, content);
                }
            }
            catch { }
        }

        private void IsFirstRun()
        {
            if (!Directory.Exists(clientlocation))
            {
                Directory.CreateDirectory(clientlocation);
                FirstRun = true;
                return;
            }

            if (!File.Exists(cfgpath))
            {
                FirstRun = true;
            }
            else
            {
                try
                {
                    var content = File.ReadAllText(cfgpath);
                    FirstRun = !content.Contains("installed=true");
                }
                catch
                {
                    FirstRun = true;
                }
            }
        }

        private void CheckProtocolRegistration()
        {
            string expectedCommand = $"\"{launcherpath}\" \"%1\"";
            foreach (string protocol in new[] { Protocol, LegacyProtocol })
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey($@"Software\Classes\{protocol}\shell\open\command");
                string? command = key?.GetValue("") as string;
                if (!string.Equals(command?.Trim(), expectedCommand, StringComparison.OrdinalIgnoreCase))
                {
                    NeedsRegistration = true;
                    return;
                }
            }
        }

        private bool IsCurrentClientInstalled()
        {
            if (!File.Exists(ClientExe) || !File.Exists(cfgpath))
                return false;

            try
            {
                string config = File.ReadAllText(cfgpath);
                if (!config.Contains("installed=true", StringComparison.OrdinalIgnoreCase)
                    || !config.Contains($"client-version={ClientVersion}", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                using FileStream executable = File.OpenRead(ClientExe);
                using SHA256 sha256 = SHA256.Create();
                string actualHash = Convert.ToHexString(sha256.ComputeHash(executable));
                return actualHash.Equals(ClientExecutableSha256, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private bool HasExpectedClientAppSettings()
        {
            try
            {
                string appSettingsPath = Path.Combine(ClientDir, "AppSettings.xml");
                return File.Exists(appSettingsPath)
                    && File.ReadAllText(appSettingsPath).Equals(ExpectedClientAppSettings, StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        private void WriteAndVerifyClientAppSettings()
        {
            string appSettingsPath = Path.Combine(ClientDir, "AppSettings.xml");
            File.WriteAllText(appSettingsPath, ExpectedClientAppSettings);

            string writtenSettings = File.ReadAllText(appSettingsPath);
            if (!writtenSettings.Equals(ExpectedClientAppSettings, StringComparison.Ordinal))
                throw new IOException("AppSettings.xml could not be verified after it was written.");
        }

        private void RemoveLocalClientSettingsOverride()
        {

            string settingsDirectory = Path.Combine(ClientDir, "ClientSettings");
            string overridePath = Path.Combine(settingsDirectory, "ClientAppSettings.json");
            if (File.Exists(overridePath))
                File.Delete(overridePath);

            if (Directory.Exists(settingsDirectory)
                && Directory.GetFileSystemEntries(settingsDirectory).Length == 0)
            {
                Directory.Delete(settingsDirectory);
            }
        }

        private static bool HasExpectedLegacyPolicyStorage(string storagePath)
        {
            try
            {
                using JsonDocument storage = JsonDocument.Parse(File.ReadAllText(storagePath));
                if (storage.RootElement.ValueKind != JsonValueKind.Object)
                    return false;

                var propertyNames = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty property in storage.RootElement.EnumerateObject())
                {
                    if (!propertyNames.Add(property.Name)
                        || property.Value.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }
                }

                return storage.RootElement.TryGetProperty("PolicyServiceHttpResponse", out JsonElement response)
                    && response.ValueKind == JsonValueKind.String
                    && response.GetString() == LegacyPolicyResponseJson;
            }
            catch
            {
                return false;
            }
        }

        private void PrepareRobloxPolicyStorage()
        {

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localAppData))
                throw new IOException("Windows did not provide a Local AppData path for the policy-cache backup.");

            string resetMarker = Path.Combine(clientlocation, "policy-cache-reset-v3.done");
            string storagePath = Path.Combine(localAppData, "Roblox", "LocalStorage", "appStorage.json");
            const string mutexName = @"Local\HexiumPolicyStorageResetV3";

            using var resetMutex = new Mutex(false, mutexName);
            bool ownsMutex = false;
            try
            {
                try
                {
                    ownsMutex = resetMutex.WaitOne(TimeSpan.FromSeconds(10));
                }
                catch (AbandonedMutexException)
                {
                    ownsMutex = true;
                }

                if (!ownsMutex)
                {
                    throw new IOException(
                        "Another Hexium launcher is still preparing Roblox LocalStorage. Close the other launcher and try again."
                    );
                }

                if (HasExpectedLegacyPolicyStorage(storagePath))
                {
                    WriteLog("Legacy Roblox policy storage is already prepared.");
                    try
                    {
                        File.WriteAllText(
                            resetMarker,
                            $"UTC={DateTime.UtcNow:o}\r\n" +
                            $"LauncherVersion={LauncherVersion}\r\n" +
                            "Result=AlreadySeeded\r\n" +
                            $"OriginalPath={storagePath}\r\n" +
                            "BackupPath=\r\n"
                        );
                    }
                    catch (Exception ex)
                    {
                        WriteLog($"Policy storage was valid, but its marker could not be written: {ex.Message}");
                    }
                    return;
                }

                string backupPath = "";
                bool backedUp = false;
                string originalStorageHash = "";
                var storageValues = new Dictionary<string, string>(StringComparer.Ordinal);
                if (File.Exists(storagePath))
                {
                    originalStorageHash = ComputeFileSha256(storagePath);

                    string backupDirectory = Path.Combine(localAppData, "HexiumBackups", "RobloxLocalStorage");
                    Directory.CreateDirectory(backupDirectory);

                    string timestamp = DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffffffZ");
                    string uniqueSuffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                    backupPath = Path.Combine(
                        backupDirectory,
                        $"appStorage-before-policy-reset-v3-{timestamp}-{uniqueSuffix}.json"
                    );

                    try
                    {
                        using JsonDocument existingStorage = JsonDocument.Parse(File.ReadAllText(storagePath));
                        if (existingStorage.RootElement.ValueKind == JsonValueKind.Object)
                        {
                            foreach (JsonProperty property in existingStorage.RootElement.EnumerateObject())
                            {

                                if (property.Value.ValueKind == JsonValueKind.String)
                                {
                                    storageValues[property.Name] = property.Value.GetString() ?? "";
                                }
                                else
                                {
                                    WriteLog($"Skipped unsupported non-string Roblox LocalStorage key: {property.Name}");
                                }
                            }
                        }
                        else
                        {
                            WriteLog("Roblox appStorage.json did not contain a JSON object; recreating it while retaining the exact backup.");
                        }
                    }
                    catch (Exception ex) when (ex is JsonException || ex is IOException || ex is UnauthorizedAccessException)
                    {
                        WriteLog($"Roblox appStorage.json could not be parsed; recreating it while retaining the exact backup: {ex.Message}");
                    }
                }

                string storageDirectory = Path.GetDirectoryName(storagePath)
                    ?? throw new IOException("Could not determine the Roblox LocalStorage directory.");
                Directory.CreateDirectory(storageDirectory);

                storageValues["PolicyServiceHttpResponse"] = LegacyPolicyResponseJson;
                string seededStorageJson = JsonSerializer.Serialize(storageValues);
                string temporaryPath = Path.Combine(
                    storageDirectory,
                    $".appStorage.hexium-{Guid.NewGuid():N}.tmp"
                );
                try
                {
                    byte[] preparedBytes = Encoding.UTF8.GetBytes(seededStorageJson);
                    using (FileStream preparedFile = new FileStream(
                        temporaryPath,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.None
                    ))
                    {
                        preparedFile.Write(preparedBytes, 0, preparedBytes.Length);
                        preparedFile.Flush(flushToDisk: true);
                    }

                    if (!HasExpectedLegacyPolicyStorage(temporaryPath))
                        throw new IOException("Hexium could not verify the prepared temporary policy storage.");

                    if (File.Exists(storagePath))
                    {

                        string currentStorageHash = ComputeFileSha256(storagePath);
                        if (!currentStorageHash.Equals(originalStorageHash, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new IOException(
                                "Roblox LocalStorage changed while Hexium was preparing it. " +
                                "Close every Roblox window and try again; no cache file was changed by Hexium."
                            );
                        }

                        File.Replace(temporaryPath, storagePath, backupPath, ignoreMetadataErrors: true);
                        backedUp = true;
                        WriteLog($"Atomically backed up Roblox LocalStorage to: {backupPath}");
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(originalStorageHash))
                        {
                            throw new IOException(
                                "Roblox LocalStorage disappeared while Hexium was preparing it. " +
                                "Close every Roblox window and try again; no cache file was changed by Hexium."
                            );
                        }

                        File.Move(temporaryPath, storagePath);
                    }
                }
                finally
                {
                    try
                    {
                        if (File.Exists(temporaryPath))
                            File.Delete(temporaryPath);
                    }
                    catch { }
                }

                if (!HasExpectedLegacyPolicyStorage(storagePath))
                    throw new IOException("Hexium could not verify the prepared Roblox policy storage.");

                WriteLog("Prepared Roblox LocalStorage with the verified classic-menu policy response.");
                string markerContent =
                    $"UTC={DateTime.UtcNow:o}\r\n" +
                    $"LauncherVersion={LauncherVersion}\r\n" +
                    $"Result={(backedUp ? "BackedUpAndUpdated" : "CreatedAndSeeded")}\r\n" +
                    $"OriginalPath={storagePath}\r\n" +
                    $"BackupPath={backupPath}\r\n";
                try
                {
                    File.WriteAllText(resetMarker, markerContent);
                }
                catch (Exception ex)
                {

                    WriteLog($"Policy storage was prepared, but its marker could not be written: {ex.Message}");
                }
            }
            finally
            {
                if (ownsMutex)
                    resetMutex.ReleaseMutex();
            }
        }

        private void RepairRobloxHttpCacheOnce()
        {

            string markerPath = Path.Combine(clientlocation, "avatar-http-cache-repair-v5.done");
            if (File.Exists(markerPath))
            {
                WriteLog("Legacy Roblox HTTP cache repair is already complete.");
                return;
            }

            string tempPath = Path.GetTempPath();
            if (string.IsNullOrWhiteSpace(tempPath))
                throw new IOException("Windows did not provide a temporary-files path for the avatar cache repair.");

            string robloxTempPath = Path.GetFullPath(Path.Combine(tempPath, "Roblox"));
            string httpCachePath = Path.GetFullPath(Path.Combine(robloxTempPath, "http"));
            string? cacheParent = Path.GetDirectoryName(httpCachePath);
            if (cacheParent == null
                || !cacheParent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Equals(
                        robloxTempPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                        StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(httpCachePath).Equals("http", StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("The legacy Roblox HTTP cache path could not be validated safely.");
            }

			if (Directory.Exists(robloxTempPath)
				&& (File.GetAttributes(robloxTempPath) & FileAttributes.ReparsePoint) != 0)
			{
				throw new IOException("The legacy Roblox temporary directory is an unsafe filesystem link.");
			}

            const string mutexName = @"Local\HexiumAvatarHttpCacheRepairV5";
            using var repairMutex = new Mutex(false, mutexName);
            bool ownsMutex = false;
            try
            {
                try
                {
                    ownsMutex = repairMutex.WaitOne(TimeSpan.FromSeconds(10));
                }
                catch (AbandonedMutexException)
                {
                    ownsMutex = true;
                }

                if (!ownsMutex)
                {
                    throw new IOException(
                        "Another Hexium launcher is still repairing the avatar cache. Close it and try again."
                    );
                }

                if (File.Exists(markerPath))
                    return;

                bool cacheExisted = Directory.Exists(httpCachePath);
                if (cacheExisted)
                {
					if (Directory.Exists(robloxTempPath)
						&& (File.GetAttributes(robloxTempPath) & FileAttributes.ReparsePoint) != 0)
					{
						throw new IOException("The legacy Roblox temporary directory became an unsafe filesystem link.");
					}

                    FileAttributes attributes = File.GetAttributes(httpCachePath);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("The legacy Roblox HTTP cache path is an unsafe filesystem link.");

                    Directory.Delete(httpCachePath, recursive: true);
                }

                if (Directory.Exists(httpCachePath))
                    throw new IOException("The stale legacy Roblox HTTP cache could not be removed.");

                Directory.CreateDirectory(clientlocation);
                File.WriteAllText(
                    markerPath,
                    $"UTC={DateTime.UtcNow:o}\r\n" +
                    $"LauncherVersion={LauncherVersion}\r\n" +
                    $"CacheExisted={cacheExisted}\r\n"
                );
                WriteLog(cacheExisted
                    ? "Cleared the stale legacy Roblox HTTP cache for the avatar repair."
                    : "Legacy Roblox HTTP cache was already clean; recorded the avatar repair.");
            }
            finally
            {
                if (ownsMutex)
                    repairMutex.ReleaseMutex();
            }
        }

        internal static string ComputeFileSha256(string path)
        {
            using FileStream stream = File.OpenRead(path);
            using SHA256 sha256 = SHA256.Create();
            return Convert.ToHexString(sha256.ComputeHash(stream));
        }

        private void CleanupOldUpdates()
        {
            try
            {
                string updatesDirectory = Path.Combine(clientlocation, "Updates");
                if (!Directory.Exists(updatesDirectory))
                    return;

                foreach (string update in Directory.GetFiles(updatesDirectory, "HexiumLauncher-Update-*.exe"))
                {
                    try { File.Delete(update); } catch { }
                }
            }
            catch { }
        }

        private async Task<bool> TryStartLauncherUpdate()
        {
            string? downloadedUpdate = null;
            try
            {
                status.Text = "Checking for launcher updates...";
                progress.Style = ProgressBarStyle.Marquee;
                progress.MarqueeAnimationSpeed = 25;
                this.Refresh();

                using var http = HexiumTls.CreateHttpClient(TimeSpan.FromSeconds(45));
                http.DefaultRequestHeaders.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue
                {
                    NoCache = true,
                    NoStore = true
                };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("HexiumLauncher/" + LauncherVersion);

                string manifestUrl = UpdateManifestUrl + "?t=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                string manifestJson = await http.GetStringAsync(manifestUrl);
                var manifest = JsonSerializer.Deserialize<LauncherUpdateManifest>(
                    manifestJson,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (manifest == null
                    || !Version.TryParse(manifest.Version, out Version? availableVersion)
                    || !Version.TryParse(LauncherVersion, out Version? currentVersion)
                    || manifest.Sha256.Length != 64
                    || manifest.Size <= 0
                    || manifest.Size > MaximumLauncherDownloadBytes)
                {
                    throw new InvalidDataException("The launcher update manifest was invalid.");
                }

                if (!Uri.TryCreate(manifest.Url, UriKind.Absolute, out Uri? updateUri)
                    || updateUri.Scheme != Uri.UriSchemeHttps
                    || !updateUri.Host.Equals("hexium.zip", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("The launcher update URL was not an approved Hexium URL.");
                }

                string selfPath = Process.GetCurrentProcess().MainModule?.FileName
                    ?? throw new IOException("Could not determine the running launcher path.");
                string currentHash = ComputeFileSha256(selfPath);
                int versionComparison = availableVersion.CompareTo(currentVersion);
                if (versionComparison < 0
                    || (versionComparison == 0
                        && currentHash.Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase)))
                {
                    progress.Style = ProgressBarStyle.Continuous;
                    progress.Value = 0;
                    return false;
                }

                Installing = true;
                status.Text = $"Updating Hexium Launcher to {availableVersion}...";
                string updatesDirectory = Path.Combine(clientlocation, "Updates");
                Directory.CreateDirectory(updatesDirectory);
                downloadedUpdate = Path.Combine(
                    updatesDirectory,
                    $"HexiumLauncher-Update-{Guid.NewGuid():N}.exe");

                using HttpResponseMessage response = await http.GetAsync(updateUri, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();
                long? contentLength = response.Content.Headers.ContentLength;
                if (contentLength.HasValue
                    && (contentLength.Value != manifest.Size || contentLength.Value > MaximumLauncherDownloadBytes))
                {
                    throw new InvalidDataException("The launcher update size did not match its manifest.");
                }

                await using (Stream source = await response.Content.ReadAsStreamAsync())
                await using (FileStream destination = new FileStream(
                    downloadedUpdate,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    81920,
                    useAsync: true))
                {
                    await source.CopyToAsync(destination);
                }

                var downloadedInfo = new FileInfo(downloadedUpdate);
                if (downloadedInfo.Length != manifest.Size
                    || !ComputeFileSha256(downloadedUpdate).Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("The launcher update failed its SHA-256 integrity check.");
                }

                var updater = new ProcessStartInfo
                {
                    FileName = downloadedUpdate,
                    UseShellExecute = false,
                    WorkingDirectory = updatesDirectory
                };
                updater.ArgumentList.Add("--apply-update");
                updater.ArgumentList.Add(Process.GetCurrentProcess().Id.ToString());
                updater.ArgumentList.Add(launcherpath);
                updater.ArgumentList.Add(manifest.Sha256);
                updater.ArgumentList.Add(rawUrl);
                Process.Start(updater);

                BeginInvoke((MethodInvoker)(() => Application.Exit()));
                return true;
            }
            catch (Exception ex)
            {
                WriteLog("Launcher update check failed: " + Program.DescribeException(ex));
                if (!string.IsNullOrWhiteSpace(downloadedUpdate))
                {
                    try { File.Delete(downloadedUpdate); } catch { }
                }

                progress.Style = ProgressBarStyle.Continuous;
                progress.Value = 0;
                return false;
            }
        }

        private string VoiceHelperPath => Path.Combine(clientlocation, "HexiumVoice.exe");

        private async Task StartVoiceHelperAsync(string ticket, int clientPid)
        {
            if (string.IsNullOrWhiteSpace(ticket))
            {
                WriteLog("Voice helper skipped: no ticket for this launch.");
                return;
            }

            if (!await EnsureVoiceHelperAsync())
                return;

            foreach (var existing in Process.GetProcessesByName("HexiumVoice"))
            {
                try
                {
                    if (existing.HasExited)
                        continue;
                    WriteLog($"Stopping stale voice helper (pid {existing.Id}).");
                    existing.Kill();
                    existing.WaitForExit(3000);
                }
                catch (Exception ex)
                {
                    WriteLog("Could not stop stale voice helper: " + ex.Message);
                }
                finally
                {
                    existing.Dispose();
                }
            }

            var voiceInfo = new ProcessStartInfo
            {
                FileName = VoiceHelperPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = clientlocation,
            };
            voiceInfo.ArgumentList.Add("--ticket");
            voiceInfo.ArgumentList.Add(ticket);
            voiceInfo.ArgumentList.Add("--base-url");
            voiceInfo.ArgumentList.Add(SiteBaseUrl);
            if (clientPid > 0)
            {
                voiceInfo.ArgumentList.Add("--watch-pid");
                voiceInfo.ArgumentList.Add(clientPid.ToString());
            }

            Process.Start(voiceInfo);
            WriteLog($"Voice helper started (watching pid {clientPid}).");
        }

        private async Task<bool> EnsureVoiceHelperAsync()
        {
            try
            {
                if (File.Exists(VoiceHelperPath)
                    && ComputeFileSha256(VoiceHelperPath).Equals(VoiceHelperSha256, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                WriteLog("Downloading voice helper...");
                var temp = VoiceHelperPath + ".incoming";
                if (File.Exists(temp))
                    File.Delete(temp);

                using (var http = HexiumTls.CreateHttpClient())
                {
                    http.Timeout = TimeSpan.FromMinutes(10);
                    http.DefaultRequestHeaders.UserAgent.ParseAdd("HexiumLauncher/" + LauncherVersion);
                    using var response = await http.GetAsync(VoiceHelperUrl, HttpCompletionOption.ResponseHeadersRead);
                    response.EnsureSuccessStatusCode();
                    await using var source = await response.Content.ReadAsStreamAsync();
                    await using var destination = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    await source.CopyToAsync(destination);
                }

                if (!ComputeFileSha256(temp).Equals(VoiceHelperSha256, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(temp);
                    WriteLog("Voice helper failed its integrity check; voice disabled for this launch.");
                    return false;
                }

                File.Move(temp, VoiceHelperPath, true);
                WriteLog("Voice helper installed.");
                return true;
            }
            catch (Exception ex)
            {
                WriteLog($"Voice helper download failed: {ex.Message}");
                return false;
            }
        }

        private bool InstallLauncherCopy()
        {
            string selfPath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            if (string.IsNullOrWhiteSpace(selfPath) || !File.Exists(selfPath))
                throw new IOException("Could not determine the running launcher path.");

            bool copied = !string.Equals(selfPath, launcherpath, StringComparison.OrdinalIgnoreCase);
            if (copied)
                File.Copy(selfPath, launcherpath, overwrite: true);

            if (!File.Exists(launcherpath)
                || !ComputeFileSha256(selfPath).Equals(ComputeFileSha256(launcherpath), StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("The installed launcher copy did not match the downloaded launcher.");
            }

            return copied;
        }

        private void Init()
        {
            this.Text = "Hexium Launcher";
            this.ClientSize = new System.Drawing.Size(400, 210);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.BackColor = System.Drawing.Color.White;
            this.StartPosition = FormStartPosition.CenterScreen;

            try
            {
                using var iconStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("HexiumLauncher.hexium.ico");
                if (iconStream != null)
                {
                    this.Icon = new System.Drawing.Icon(iconStream);
                }
            }
            catch { }

            var logo = new PictureBox
            {
                SizeMode = PictureBoxSizeMode.Zoom,
                Width = 200,
                Height = 80,
                Top = 15,
                Left = (this.ClientSize.Width - 200) / 2
            };

            try
            {
                using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("HexiumLauncher.logo_hexium.png");
                if (stream != null)
                {
                    logo.Image = System.Drawing.Image.FromStream(stream);
                }
            }
            catch { }
            this.Controls.Add(logo);

            status = new Label
            {
                Top = 100,
                Left = 20,
                Width = this.ClientSize.Width - 40,
                Height = 25,
                TextAlign = System.Drawing.ContentAlignment.MiddleCenter,
                Font = new System.Drawing.Font("Segoe UI", 9f),
                Text = FirstRun ? "Installing Hexium..." : "Launching Hexium..."
            };
            this.Controls.Add(status);

            progress = new ProgressBar
            {
                Top = 130,
                Left = 20,
                Width = this.ClientSize.Width - 40,
                Height = 20,
                Style = ProgressBarStyle.Continuous
            };
            this.Controls.Add(progress);

            cancelBtn = new Button
            {
                Text = "Cancel",
                Top = 165,
                Left = (this.ClientSize.Width - 90) / 2,
                Width = 90,
                Height = 28,
                FlatStyle = FlatStyle.System
            };
            cancelBtn.Click += (s, e) =>
            {
                if (Installing)
                    CancelInstall();
                else
                    this.Close();
            };
            this.Controls.Add(cancelBtn);
        }

        private async void Start()
        {
            try
            {
                await Task.Delay(100);

                if (await TryStartLauncherUpdate())
                    return;

                bool devMode = await CheckDevClientModeAsync();
                ConfigureClientProfile(devMode);

                bool needsClientInstall = !IsCurrentClientInstalled();
                bool clientSettingsChanged = !HasExpectedClientAppSettings();
                bool needsSetup = needsClientInstall || clientSettingsChanged || FirstRun || NeedsRegistration;
                Installing = needsSetup;

                if (needsClientInstall)
                {
                    StopLegacyClientProcesses();
                    this.Text = "Hexium Installer";
                    status.Text = $"Downloading {ClientDisplayName}...";
                    this.Refresh();
                    await DownloadVersion();
                }

                if (!Directory.Exists(clientlocation))
                {
                    Directory.CreateDirectory(clientlocation);
                }

                WriteAndVerifyClientAppSettings();
                RemoveLocalClientSettingsOverride();

                bool launcherUpdated = InstallLauncherCopy();

                bool setupCompleted = needsSetup || launcherUpdated;
                if (setupCompleted)
                {
                    RegisterProtocol();
                    VerifyProtocolRegistration();
                    File.WriteAllText(
                        cfgpath,
                        $"installed=true\r\nclient-version={ClientVersion}\r\nlauncher-version={LauncherVersion}\r\n");
                }

                if (setupCompleted)
                {
                    ShowCompleteMsg();
                }

                Installing = false;

                if (!string.IsNullOrEmpty(placeId) && !string.IsNullOrEmpty(ticket))
                {
                    await Launch();
                }
                else if (!setupCompleted)
                {
                    ShowInstalledMessage();
                }
                else
                {
                    this.Close();
                }
            }
            catch (Exception ex)
            {
                var detail = Program.DescribeException(ex);
                WriteLog("Start error: " + detail);
                MessageBox.Show(
                    detail + "\n\n" + HexiumTls.AdviceFor(ex)
                           + "\n\nThis has also been written to launcher.log.",
                    "Hexium Launcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                this.Close();
            }
        }

        private void ShowCompleteMsg()
        {
            this.Invoke((MethodInvoker)(() =>
            {
                progress.Style = ProgressBarStyle.Continuous;
                progress.Value = 100;
            }));

            status.Text = "Installation Completed!";
            MessageBox.Show("Hexium installed! You can now join games from the website.",
                          "Hexium Client",
                          MessageBoxButtons.OK,
                          MessageBoxIcon.Information);
        }

        private void ShowInstalledMessage()
        {
            var result = MessageBox.Show("Would you like to uninstall Hexium?",
                                       "Hexium Client",
                                       MessageBoxButtons.YesNo,
                                       MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                Task.Run(() =>
                {
                    Uninstall();
                });
            }
            else
            {
                this.Close();
            }
        }

        private void CancelInstall()
        {
            CleanFilesAndRegistry();
            Application.Exit();
        }

        private static bool IsPathUnder(string candidate, string root)
        {
            string normalizedCandidate = Path.GetFullPath(candidate);
            string normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            return normalizedCandidate.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
        }

        private void StopLegacyClientProcesses()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string[] installRoots =
            {
                Path.Combine(localAppData, "Hexium"),
                Path.Combine(localAppData, "Hexium2020Fix"),
                Path.Combine(localAppData, "BubbaBlox")
            };
            string[] processNames =
            {
                "HexiumPlayer",
                "DevHexiumPlayerBeta",
                "BubbaBlox",
                "BBPlayerBeta",
                "ProjectXPlayerBeta",
                "RobloxPlayerBeta"
            };
            int currentId = Process.GetCurrentProcess().Id;

            foreach (string processName in processNames)
            {
                foreach (Process process in Process.GetProcessesByName(processName))
                {
                    using (process)
                    {
                        try
                        {
                            if (process.Id == currentId)
                                continue;

                            string? executablePath = process.MainModule?.FileName;
                            if (string.IsNullOrWhiteSpace(executablePath)
                                || !Array.Exists(installRoots, root => IsPathUnder(executablePath, root)))
                            {
                                continue;
                            }

                            WriteLog($"Stopping stale client process from {executablePath}");
                            process.Kill(entireProcessTree: true);
                            if (!process.WaitForExit(5000))
                                WriteLog($"Stale {processName} process did not exit within five seconds.");
                        }
                        catch (Exception ex)
                        {
                            WriteLog($"Could not stop stale {processName} process: {ex.Message}");
                        }
                    }
                }
            }

            foreach (string processName in processNames)
            {
                foreach (Process process in Process.GetProcessesByName(processName))
                {
                    using (process)
                    {
                        try
                        {
                            if (process.Id == currentId)
                                continue;

                            string? executablePath = process.MainModule?.FileName;
                            if (string.IsNullOrWhiteSpace(executablePath))
                                continue;

                            if (Array.Exists(installRoots, root => IsPathUnder(executablePath, root)))
                            {
                                throw new IOException(
                                    $"Hexium could not close the previous {processName} process. " +
                                    "Close every Hexium/Roblox game window and try again."
                                );
                            }

                            if (processName.Equals("RobloxPlayerBeta", StringComparison.OrdinalIgnoreCase))
                            {
                                throw new IOException(
                                    "Another Roblox game is open and could overwrite the menu policy cache. " +
                                    "Close the other Roblox game and try Hexium again."
                                );
                            }
                        }
                        catch (IOException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            WriteLog($"Could not verify whether stale {processName} exited: {ex.Message}");
                        }
                    }
                }
            }
        }

        private void CleanFilesAndRegistry()
        {
            try { StopLegacyClientProcesses(); } catch { }

            try { Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\{Protocol}", false); } catch { }
            try { Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\{LegacyProtocol}", false); } catch { }
            try { Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false); } catch { }

            if (Directory.Exists(clientlocation))
            {
                for (int i = 0; i < 5; i++)
                {
                    try
                    {
                        Directory.Delete(clientlocation, true);
                        break;
                    }
                    catch
                    {
                        Thread.Sleep(500);
                    }
                }
            }
        }

        private void Uninstall()
        {
            try
            {
                this.Invoke((MethodInvoker)(() =>
                {
                    progress.Style = ProgressBarStyle.Marquee;
                    progress.MarqueeAnimationSpeed = 30;
                    status.Text = "Uninstalling Hexium...";
                    cancelBtn.Enabled = false;
                }));

                try
                {
                    string shortcutPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Hexium");
                    if (Directory.Exists(shortcutPath))
                    {
                        Directory.Delete(shortcutPath, true);
                    }
                }
                catch { }

                CleanFilesAndRegistry();

                MessageBox.Show("Hexium has been uninstalled successfully.",
                             "Hexium Client",
                             MessageBoxButtons.OK,
                             MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to uninstall: {ex.Message}",
                              "Hexium Client - Error",
                              MessageBoxButtons.OK,
                              MessageBoxIcon.Error);
            }

            Application.Exit();
        }

        private void RegisterProtocol()
        {
            try
            {
                foreach (string protocol in new[] { Protocol, LegacyProtocol })
                {
                    using RegistryKey key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{protocol}");
                    key.SetValue("", "URL:Hexium Protocol");
                    key.SetValue("URL Protocol", "");

                    using (RegistryKey defaultIcon = key.CreateSubKey("DefaultIcon"))
                    {
                        defaultIcon.SetValue("", $"\"{launcherpath}\",1");
                    }

                    using (RegistryKey commandKey = key.CreateSubKey(@"shell\open\command"))
                    {
                        commandKey.SetValue("", $"\"{launcherpath}\" \"%1\"");
                    }
                }

                using (RegistryKey uninstallKey = Registry.CurrentUser.CreateSubKey(UninstallKey))
                {
                    uninstallKey.SetValue("DisplayName", "Hexium");
                    uninstallKey.SetValue("DisplayIcon", launcherpath);
                    uninstallKey.SetValue("UninstallString", $"\"{launcherpath}\"");
                    uninstallKey.SetValue("InstallLocation", clientlocation);
                    uninstallKey.SetValue("Publisher", "Hexium");
                    uninstallKey.SetValue("DisplayVersion", LauncherVersion);
                    uninstallKey.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    uninstallKey.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                }

                try
                {
                    string shortcutDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Hexium");
                    Directory.CreateDirectory(shortcutDir);
                    File.WriteAllText(Path.Combine(shortcutDir, "Hexium.url"),
                        $"[InternetShortcut]\r\nURL=hexium://\r\nIconFile={launcherpath}\r\nIconIndex=0\r\n");
                }
                catch { }

                NeedsRegistration = false;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to register the Hexium protocol: {ex.Message}", ex);
            }
        }

        private void VerifyProtocolRegistration()
        {
            string expectedCommand = $"\"{launcherpath}\" \"%1\"";
            foreach (string protocol in new[] { Protocol, LegacyProtocol })
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey($@"Software\Classes\{protocol}\shell\open\command");
                string? actualCommand = key?.GetValue("") as string;
                if (!string.Equals(actualCommand?.Trim(), expectedCommand, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"The {protocol} protocol did not point to HexiumLauncher.exe.");
            }
        }

        private async Task DownloadVersion()
        {

            ServicePointManager.ServerCertificateValidationCallback = HexiumTls.Validate;
            using (var client = new WebClient())
            {
                client.Headers[HttpRequestHeader.UserAgent] = "HexiumLauncher/" + LauncherVersion;

                this.Invoke((MethodInvoker)(() =>
                {
                    progress.Style = ProgressBarStyle.Continuous;
                    progress.Minimum = 0;
                    progress.Maximum = 100;
                    progress.Value = 0;
                }));

                client.DownloadProgressChanged += (s, e) =>
                {
                    this.Invoke((MethodInvoker)(() =>
                    {
                        progress.Value = Math.Min(e.ProgressPercentage, 100);
                        status.Text = $"Downloading {ClientDisplayName}... {e.ProgressPercentage}%";
                    }));
                };

                await client.DownloadFileTaskAsync(DownloadUrl, ClientZIP);

                using (FileStream archive = File.OpenRead(ClientZIP))
                using (SHA256 sha256 = SHA256.Create())
                {
                    string actualHash = Convert.ToHexString(sha256.ComputeHash(archive));
                    if (!actualHash.Equals(ClientArchiveSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Delete(ClientZIP);
                        throw new InvalidDataException(
                            $"Client archive integrity check failed. Expected {ClientArchiveSha256}, got {actualHash.ToLowerInvariant()}."
                        );
                    }
                }

                this.Invoke((MethodInvoker)(() =>
                {
                    progress.Value = 100;
                    progress.Style = ProgressBarStyle.Marquee;
                    progress.MarqueeAnimationSpeed = 30;
                    status.Text = $"Extracting {ClientDisplayName}...";
                }));

                try
                {
                    if (File.Exists(ClientZIP))
                    {
                        if (Directory.Exists(ClientDir))
                        {
                            Directory.Delete(ClientDir, true);
                        }

                        await Task.Run(() =>
                        {

                            ZipFile.ExtractToDirectory(ClientZIP, clientlocation, true);
                        });

                        File.Delete(ClientZIP);
                    }

                    if (!File.Exists(ClientExe))
                    {
                        throw new InvalidDataException($"The downloaded archive did not contain {Path.GetFileName(ClientExe)}.");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Extraction failed: {ex.Message}", "Hexium Client - Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    throw;
                }

                try
                {
                    WriteAndVerifyClientAppSettings();
                }
                catch (Exception ex)
                {
                    throw new IOException($"Failed to configure the required AppSettings.xml: {ex.Message}", ex);
                }
            }
        }

        private Exception? lastPollFailure;

        private async Task<bool> WaitPlaceLauncherReady(string url)
        {
            lastPollFailure = null;
            using (var http = HexiumTls.CreateHttpClient())
            {
                http.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HexiumLauncher");
                for (int attempt = 1; attempt <= 60; attempt++)
                {
                    WriteLog($"Waiting for game server, attempt {attempt}");
                    this.Invoke((MethodInvoker)(() =>
                    {
                        status.Text = $"Waiting for game server... (Attempt {attempt}/60)";
                    }));

                    try
                    {
                        var response = await http.GetStringAsync(url);
                        using var document = JsonDocument.Parse(response);
                        var root = document.RootElement;
                        int serverStatus = root.TryGetProperty("status", out var statusProperty)
                            ? statusProperty.GetInt32()
                            : -1;
                        bool hasJoinUrl = root.TryGetProperty("joinScriptUrl", out var joinUrlProperty)
                            && !string.IsNullOrWhiteSpace(joinUrlProperty.GetString());

                        WriteLog($"PlaceLauncher status: {serverStatus}");
                        if (serverStatus == 2 && hasJoinUrl)
                        {
                            WriteLog("Server is ready.");
                            return true;
                        }
                        if (serverStatus >= 3)
                        {
                            WriteLog($"PlaceLauncher returned error status {serverStatus}.");
                            return false;
                        }
                    }
                    catch (Exception ex)
                    {

                        lastPollFailure = ex;
                        WriteLog($"Attempt {attempt} failed: {Program.DescribeException(ex)}");
                    }
                    await Task.Delay(1000);
                }
            }
            WriteLog("Timed out waiting for game server");
            return false;
        }

        private async Task Launch()
        {
            try
            {
                if (!File.Exists(ClientExe))
                {
                    MessageBox.Show($"Client not found at: {ClientExe}", "Hexium Client - Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                try
                {
                    WriteAndVerifyClientAppSettings();
                    WriteLog($"Updated and verified AppSettings.xml BaseUrl: {ClientSettingsBaseUrl}");
                }
                catch (Exception ex)
                {
                    WriteLog($"Failed to update AppSettings.xml: {ex.Message}");
                    MessageBox.Show(
                        $"Hexium could not apply its required client settings, so the player was not started.\n\nError: {ex.Message}",
                        "Hexium Client - Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    this.Close();
                    return;
                }

                this.Invoke((MethodInvoker)(() =>
                {
                    progress.Style = ProgressBarStyle.Marquee;
                    progress.MarqueeAnimationSpeed = 30;
                    status.Text = "Waiting for server...";
                }));

                string encodedPlaceId = Uri.EscapeDataString(placeId);
                string encodedTicket = Uri.EscapeDataString(ticket);
                string joinUrl = $"{SiteBaseUrl}/game/PlaceLauncher.ashx?placeid={encodedPlaceId}&ticket={encodedTicket}&{this.year}=true";
                if (!string.IsNullOrEmpty(jobId))
                {
                    joinUrl += $"&jobId={Uri.EscapeDataString(jobId)}";
                }

                WriteLog($"Connecting to PlaceLauncher for place {encodedPlaceId}{(string.IsNullOrEmpty(jobId) ? "" : $" server {jobId}")} using the 2020 client.");

                bool serverReady = await WaitPlaceLauncherReady(joinUrl);
                if (!serverReady)
                {
                    var pollMessage = lastPollFailure == null
                        ? "Failed to connect to the Hexium server because the server is not ready or timed out."
                        : "Could not reach the Hexium server. Every attempt failed with:\n\n"
                          + Program.DescribeException(lastPollFailure)
                          + "\n\n" + HexiumTls.AdviceFor(lastPollFailure)
                          + "\n\nThis has also been written to launcher.log.";
                    MessageBox.Show(pollMessage, "Hexium Client - Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.Close();
                    return;
                }

                this.Invoke((MethodInvoker)(() =>
                {
                    status.Text = "Starting Hexium...";
                }));
                this.Refresh();

                string arguments = $"-a \"{SiteBaseUrl}/Login/Negotiate.ashx\" -j \"{joinUrl}\" -t \"{ticket}\"";
                WriteLog($"Launching 2020 client: {ClientExe}");

                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = ClientExe,
                    Arguments = arguments,
                    UseShellExecute = false,
                    WorkingDirectory = ClientDir
                };

                StopLegacyClientProcesses();
                RepairRobloxHttpCacheOnce();
                PrepareRobloxPolicyStorage();
                WriteLastLaunch(placeId, year);

                var clientProcess = ProcessHardening.Start(
                    ClientExe, arguments, ClientDir, WriteLog);
                if (clientProcess == null)
                {
                    WriteLog("Falling back to an unhardened client start.");
                    clientProcess = Process.Start(startInfo);
                }

                try
                {
                    FpsUnlocker.StartAsync(clientProcess?.Id ?? 0, WriteLog);

                    ClientKeyResign.StartAsync(clientProcess?.Id ?? 0, ClientVersion, WriteLog);
                }
                catch (Exception fpsEx)
                {
                    WriteLog($"FPS unlocker could not be started: {fpsEx.Message}");
                }

                try
                {
                    await StartVoiceHelperAsync(ticket, clientProcess?.Id ?? 0);
                }
                catch (Exception voiceEx)
                {
                    WriteLog($"Voice helper could not be started: {voiceEx.Message}");
                }

                this.Invoke((MethodInvoker)delegate
                {
                    this.Hide();
                    this.ShowInTaskbar = false;
                });

                string gameName = await DiscordRpc.FetchGameNameAsync(SiteBaseUrl, placeId, WriteLog);
                WriteLog($"Game name resolved for Discord RPC: {gameName}");

                try
                {
                    await DiscordRpc.RunPresenceLoopAsync(
                        clientProcess?.Id ?? 0,
                        placeId,
                        gameName,
                        SiteBaseUrl,
                        WriteLog);
                }
                catch (Exception rpcEx)
                {
                    WriteLog($"Discord RPC presence loop ended: {rpcEx.Message}");
                }

                this.Invoke((MethodInvoker)delegate
                {
                    if (!this.IsDisposed)
                        this.Close();
                });
            }
            catch (Exception ex)
            {
                WriteLog($"Launch exception: {ex.Message}");
                MessageBox.Show($"Failed to launch Hexium at: {ClientExe}\n\nError: {ex.Message}", "Hexium Client - Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                this.Close();
            }
        }
    }
}
