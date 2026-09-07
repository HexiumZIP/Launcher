# Hexium Launcher

README MADE WITH AI IF YOU DONT UNDERSTAND SOMETHING ASK IN OUR DISCORD

An open-source desktop launcher and URI protocol handler for the Hexium 2020 client, built with C# and .NET WinForms.

---

## Features

- **Protocol Handler**: Registers and handles `hexium://` (and legacy `bbclient://`) URI links directly from the browser.
- **Client Management**: Automatically installs, extracts, and manages the client under `%LOCALAPPDATA%\Hexium`.
- **Integrity Verification**: Verifies SHA-256 hashes for all client archives and executables before running.
- **Automatic Updates**: Checks `/downloads/launcher-manifest.json` on launch to seamlessly download updates over HTTPS.
- **Built-in FPS Unlocker**: Memory-safe frame rate limiter adjustments to lift the 60 FPS engine cap.
- **Discord Rich Presence**: Displays in-game status, place details, and play session time on Discord.
- **Bundled TLS Trust**: Includes an embedded root certificate authority bundle (`cacert.pem`) to ensure secure HTTPS connections across all Windows versions.

---

## Building from Source

### Prerequisites
- [.NET 6.0 SDK](https://dotnet.microsoft.com/download/dotnet/6.0) or higher
- Windows 10/11 (or Linux with .NET SDK for cross-compilation)
- Optional: Visual Studio 2022 or VS Code

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_ORGANIZATION/HexiumLauncher.git
cd HexiumLauncher
```

### 2. Build Debug
```bash
dotnet build HexiumLauncher.csproj
```

### 3. Build Production Release (Self-Contained Single File)
To generate the final standalone executable that includes the .NET runtime and does not require users to install .NET separately:

```bash
dotnet publish HexiumLauncher.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o ./dist
```

The published executable will be available at `./dist/HexiumLauncher.exe`.

---

## Security & False Positive Clarification

Because Hexium Launcher interacts with the system to install files, register URI schemes, and unlock client frame rates, automated antivirus sandboxes and heuristic scanners frequently trigger false positive warnings. The source code is completely open here for full transparency and verification.

### Frequently Asked Questions & Sandbox Detections

#### 1. "Unsigned Image Loaded Into LSASS Process" (Sigma Rule)
* **What is it?** Windows delegates TLS/HTTPS certificate validation and security provider negotiations to Schannel (SSPI), which runs inside `lsass.exe` (Local Security Authority Subsystem Service).
* **Why did it flag?** When the launcher makes HTTPS requests to check for game updates, Windows SSPI/Schannel inside `lsass.exe` processes the connection. Because HexiumLauncher is an independent project without an enterprise Authenticode certificate, security sandboxes flag ANY unsigned process communicating via SSPI/TLS with this generic rule.
* **Is it touching credentials?** **No.** Hexium Launcher contains zero credential dumping, zero process injection into LSASS, and zero token manipulation. You can inspect the source code in [`Program.cs`](Program.cs) to verify all web requests are standard .NET `HttpClient` calls.

#### 2. "Sysmon File Executable Creation Detected" (Sigma Rule)
* **What is it?** This is an informational system auditing rule (Sysmon Event ID 29) that fires **every single time ANY executable (`.exe`) is written to disk**.
* **Why did it flag?** The launcher's core job is to download and extract the game client (`HexiumPlayer.exe`) into `%LOCALAPPDATA%\Hexium`. Every installer and game launcher (Steam, Epic Games, Discord) triggers this exact rule.

#### 3. "Is it a RAT or Keylogger?"
* **No.** There are:
  - **No keyboard hooks**: No calls to `SetWindowsHookEx`, `GetAsyncKeyState`, or keyboard capture APIs.
  - **No remote access tools (RAT)**: No hidden reverse shells, command execution listeners, or unauthorized network sockets.
  - **No background telemetry or credential scrapers**: The launcher only communicates with the official game endpoints to authenticate game join tickets and retrieve updates.

#### 4. Why does Windows Defender or SmartScreen show a warning?
* Windows SmartScreen warns on all newly compiled, unsigned executables that do not have thousands of downloads or an expensive EV (Extended Validation) code-signing certificate ($300–$600/year).

---

## Project Structure

| File | Description |
|---|---|
| [`Program.cs`](Program.cs) | Main launcher entry point, UI forms, update engine, SHA-256 verification, and game process launching. |
| [`HexiumLauncher.csproj`](HexiumLauncher.csproj) | .NET project configuration, build properties, and embedded resources. |
| [`FpsUnlocker.cs`](FpsUnlocker.cs) | Frame cap unlocker that adjusts the 60 FPS scheduler delay in the game process memory. |
| [`DiscordRpc.cs`](DiscordRpc.cs) | Discord Rich Presence IPC client. |
| [`ClientKeyResign.cs`](ClientKeyResign.cs) | Cryptographic signature verification and client key patch validation. |
| [`ProcessHardening.cs`](ProcessHardening.cs) | Process security mitigations and execution policy enforcement. |
| [`app.manifest`](app.manifest) | Windows application manifest defining execution privileges (`asInvoker`) and DPI awareness. |
| [`cacert.pem`](cacert.pem) | Shipped Mozilla CA certificate bundle for reliable TLS validation. |

---

## Contributing & Auditing

Feel free to audit the source code, open issues, or submit pull requests. If you prefer to run only code you compiled yourself, follow the [Building from Source](#building-from-source) instructions above.
