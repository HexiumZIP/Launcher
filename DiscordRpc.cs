using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace HexiumLauncher
{
    public static class DiscordRpc
    {
        public const string DefaultClientId = "1526299837056815226";
        private const int OpcodeHandshake = 0;
        private const int OpcodeFrame = 1;
        private const int OpcodeClose = 2;
        private const int OpcodePing = 3;
        private const int OpcodePong = 4;

        public static async Task<string> FetchGameNameAsync(string baseUrl, string placeId, Action<string>? log = null)
        {
            if (string.IsNullOrWhiteSpace(placeId))
                return "Hexium";

            try
            {
                using var http = HexiumTls.CreateHttpClient();
                http.Timeout = TimeSpan.FromSeconds(5);
                http.DefaultRequestHeaders.Add("User-Agent", "HexiumLauncher");

                string url = $"{baseUrl.TrimEnd('/')}/apisite/games/v1/games/multiget-place-details?placeIds={Uri.EscapeDataString(placeId)}";
                string json = await http.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
                {
                    var first = doc.RootElement[0];
                    if (first.TryGetProperty("name", out var nameElem) && !string.IsNullOrWhiteSpace(nameElem.GetString()))
                    {
                        return nameElem.GetString()!.Trim();
                    }
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"Could not query game name for Discord presence: {ex.Message}");
            }

            return "Hexium";
        }

        public static async Task RunPresenceLoopAsync(
            int clientPid,
            string placeId,
            string gameName,
            string siteBaseUrl,
            Action<string>? log = null,
            CancellationToken cancellationToken = default)
        {
            long startTimeUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string largeImageUrl = !string.IsNullOrWhiteSpace(placeId)
                ? $"{siteBaseUrl.TrimEnd('/')}/Thumbs/GameIcon.ashx?assetId={Uri.EscapeDataString(placeId)}&x=512&y=512&format=png"
                : $"{siteBaseUrl.TrimEnd('/')}/textures/DeveloperFramework/NewHexium_Discord_1.webp";
            string smallImageUrl = $"{siteBaseUrl.TrimEnd('/')}/textures/DeveloperFramework/NewHexium_Discord_1.webp";

            while (!cancellationToken.IsCancellationRequested)
            {
                Process? proc = null;
                if (clientPid > 0)
                {
                    try
                    {
                        proc = Process.GetProcessById(clientPid);
                        if (proc.HasExited)
                        {
                            log?.Invoke("Roblox client process exited; stopping Discord Rich Presence.");
                            break;
                        }
                    }
                    catch
                    {
                        log?.Invoke("Roblox client process not found; stopping Discord Rich Presence.");
                        break;
                    }
                }

                NamedPipeClientStream? pipe = null;
                try
                {
                    pipe = await ConnectDiscordPipeAsync(log);
                    if (pipe == null)
                    {

                        await Task.Delay(10000, cancellationToken);
                        continue;
                    }

                    var handshakePayload = new JsonObject
                    {
                        ["v"] = 1,
                        ["client_id"] = DefaultClientId
                    };
                    await WritePacketAsync(pipe, OpcodeHandshake, handshakePayload.ToJsonString());

                    var (_, _) = await ReadPacketAsync(pipe);

                    var activityPayload = new JsonObject
                    {
                        ["cmd"] = "SET_ACTIVITY",
                        ["args"] = new JsonObject
                        {
                            ["pid"] = clientPid > 0 ? clientPid : Process.GetCurrentProcess().Id,
                            ["activity"] = new JsonObject
                            {
                                ["details"] = gameName,
                                ["state"] = "Playing Hexium",
                                ["timestamps"] = new JsonObject
                                {
                                    ["start"] = startTimeUnix
                                },
                                ["assets"] = new JsonObject
                                {
                                    ["large_image"] = largeImageUrl,
                                    ["large_text"] = gameName,
                                    ["small_image"] = smallImageUrl,
                                    ["small_text"] = "Hexium"
                                },
                                ["buttons"] = new JsonArray
                                {
                                    new JsonObject
                                    {
                                        ["label"] = "Visit Revival",
                                        ["url"] = "https://hexium.zip"
                                    }
                                }
                            }
                        },
                        ["nonce"] = Guid.NewGuid().ToString("N")
                    };

                    await WritePacketAsync(pipe, OpcodeFrame, activityPayload.ToJsonString());
                    log?.Invoke($"Set Discord Rich Presence: {gameName}");

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        if (clientPid > 0)
                        {
                            try
                            {
                                if (proc == null || proc.HasExited)
                                {
                                    log?.Invoke("Client process exited.");
                                    break;
                                }
                            }
                            catch
                            {
                                break;
                            }
                        }

                        if (!pipe.IsConnected)
                        {
                            log?.Invoke("Discord pipe disconnected; will retry connection.");
                            break;
                        }

                        await Task.Delay(2000, cancellationToken);
                    }

                    if (pipe.IsConnected)
                    {
                        try
                        {
                            var clearPayload = new JsonObject
                            {
                                ["cmd"] = "SET_ACTIVITY",
                                ["args"] = new JsonObject
                                {
                                    ["pid"] = clientPid > 0 ? clientPid : Process.GetCurrentProcess().Id,
                                    ["activity"] = null
                                },
                                ["nonce"] = Guid.NewGuid().ToString("N")
                            };
                            await WritePacketAsync(pipe, OpcodeFrame, clearPayload.ToJsonString());
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    log?.Invoke($"Discord RPC error: {ex.Message}");
                    await Task.Delay(5000, cancellationToken);
                }
                finally
                {
                    if (pipe != null)
                    {
                        try { pipe.Dispose(); } catch { }
                    }
                }

                if (clientPid > 0)
                {
                    try
                    {
                        if (proc == null || proc.HasExited)
                            break;
                    }
                    catch
                    {
                        break;
                    }
                }
            }
        }

        private static async Task<NamedPipeClientStream?> ConnectDiscordPipeAsync(Action<string>? log)
        {
            for (int i = 0; i < 10; i++)
            {
                string pipeName = $"discord-ipc-{i}";
                try
                {
                    var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                    await pipe.ConnectAsync(cts.Token);
                    return pipe;
                }
                catch
                {

                }
            }
            return null;
        }

        private static async Task WritePacketAsync(NamedPipeClientStream pipe, int opcode, string json)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(json);
            byte[] header = new byte[8];
            Array.Copy(BitConverter.GetBytes(opcode), 0, header, 0, 4);
            Array.Copy(BitConverter.GetBytes(bodyBytes.Length), 0, header, 4, 4);

            await pipe.WriteAsync(header, 0, 8);
            await pipe.WriteAsync(bodyBytes, 0, bodyBytes.Length);
            await pipe.FlushAsync();
        }

        private static async Task<(int opcode, string json)> ReadPacketAsync(NamedPipeClientStream pipe)
        {
            byte[] header = new byte[8];
            int read = 0;
            while (read < 8)
            {
                int r = await pipe.ReadAsync(header, read, 8 - read);
                if (r == 0) throw new IOException("Discord pipe closed prematurely.");
                read += r;
            }

            int opcode = BitConverter.ToInt32(header, 0);
            int length = BitConverter.ToInt32(header, 4);

            byte[] body = new byte[length];
            int bodyRead = 0;
            while (bodyRead < length)
            {
                int r = await pipe.ReadAsync(body, bodyRead, length - bodyRead);
                if (r == 0) throw new IOException("Discord pipe closed prematurely.");
                bodyRead += r;
            }

            string json = Encoding.UTF8.GetString(body);
            return (opcode, json);
        }
    }
}
