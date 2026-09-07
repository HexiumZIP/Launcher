using System.Diagnostics;
using System.Runtime.InteropServices;

namespace HexiumLauncher
{

    internal static class FpsUnlocker
    {
        internal const int TargetFps = 1000;

        private const double LockedFrameDelay = 1.0 / 60.0;

        private static readonly long LockedBits = BitConverter.DoubleToInt64Bits(LockedFrameDelay);

        private const double FallbackTolerance = 0.0000000001;

        private static readonly int[] ScanAttemptDelaysMs = { 3500, 3000, 4000 };

        private const int MaxReasonableMatches = 48;

        private const int MaintainIntervalMs = 5000;
        private const int MaintainForMs = 120000;

        private const uint ProcessVmOperation = 0x0008;
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessVmWrite = 0x0020;
        private const uint ProcessQueryInformation = 0x0400;

        private const uint MemCommit = 0x1000;
        private const uint MemPrivate = 0x20000;
        private const uint PageReadWrite = 0x04;
        private const uint PageGuard = 0x100;

        private const int MaxChunk = 32 * 1024 * 1024;

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryBasicInformation
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public int Alignment1;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public int Alignment2;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address,
            out MemoryBasicInformation buffer, IntPtr length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadProcessMemory(IntPtr process, IntPtr address,
            byte[] buffer, IntPtr size, out IntPtr read);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteProcessMemory(IntPtr process, IntPtr address,
            byte[] buffer, IntPtr size, out IntPtr written);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SystemInfo info);

        [StructLayout(LayoutKind.Sequential)]
        private struct SystemInfo
        {
            public ushort ProcessorArchitecture;
            public ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        internal static void StartAsync(int processId, Action<string> log)
        {
            if (processId <= 0)
                return;

            _ = Task.Run(() =>
            {
                try
                {
                    Run(processId, log);
                }
                catch (Exception ex)
                {
                    log($"FPS unlocker stopped: {ex.Message}");
                }
            });
        }

        private static void Run(int processId, Action<string> log)
        {
            IntPtr handle = OpenProcess(
                ProcessVmOperation | ProcessVmRead | ProcessVmWrite | ProcessQueryInformation,
                false, processId);

            if (handle == IntPtr.Zero)
            {
                log($"FPS unlocker could not open the client process ({Marshal.GetLastWin32Error()}).");
                return;
            }

            try
            {
                byte[] replacement = BitConverter.GetBytes(1.0 / TargetFps);
                List<ulong> patchedAddresses = new();

                foreach (int delay in ScanAttemptDelaysMs)
                {
                    Thread.Sleep(delay);

                    if (HasExited(processId))
                    {
                        log("FPS unlocker: client closed before the sweep finished.");
                        return;
                    }

                    List<ulong> candidates = Scan(handle, exactBitsOnly: true);
                    if (candidates.Count == 0)
                    {

                        candidates = Scan(handle, exactBitsOnly: false);
                    }

                    if (candidates.Count == 0)
                    {
                        log("FPS unlocker: frame delay not found yet, retrying.");
                        continue;
                    }

                    if (candidates.Count > MaxReasonableMatches)
                    {

                        log($"FPS unlocker: {candidates.Count} candidates is implausible for the " +
                            "scheduler, so nothing was changed (staying at 60 fps is safer than a crash).");
                        return;
                    }

                    foreach (ulong candidate in candidates)
                    {
                        if (StillLocked(handle, candidate) &&
                            WriteProcessMemory(handle, (IntPtr)(long)candidate, replacement, (IntPtr)8, out _))
                        {
                            patchedAddresses.Add(candidate);
                        }
                    }

                    if (patchedAddresses.Count > 0)
                        break;
                }

                if (patchedAddresses.Count == 0)
                {
                    log("FPS unlocker: could not find the frame delay; the client stays at 60 fps.");
                    return;
                }

                log($"FPS unlocker: target {TargetFps} fps, {patchedAddresses.Count} value(s) rewritten.");
                Maintain(handle, processId, patchedAddresses, replacement, log);
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static void Maintain(IntPtr handle, int processId, List<ulong> addresses,
            byte[] replacement, Action<string> log)
        {
            int elapsed = 0;
            int reapplied = 0;

            while (elapsed < MaintainForMs)
            {
                Thread.Sleep(MaintainIntervalMs);
                elapsed += MaintainIntervalMs;

                if (HasExited(processId))
                    return;

                foreach (ulong address in addresses)
                {
                    if (StillLocked(handle, address) &&
                        WriteProcessMemory(handle, (IntPtr)(long)address, replacement, (IntPtr)8, out _))
                    {
                        reapplied++;
                    }
                }
            }

            if (reapplied > 0)
                log($"FPS unlocker: re-applied the frame delay {reapplied} time(s).");
        }

        private static bool StillLocked(IntPtr handle, ulong address)
        {
            byte[] current = new byte[8];
            if (!ReadProcessMemory(handle, (IntPtr)(long)address, current, (IntPtr)8, out IntPtr read)
                || (int)read != 8)
                return false;

            return BitConverter.ToInt64(current, 0) == LockedBits;
        }

        private static bool HasExited(int processId)
        {
            try
            {
                using Process p = Process.GetProcessById(processId);
                return p.HasExited;
            }
            catch (ArgumentException)
            {
                return true;
            }
        }

        private static List<ulong> Scan(IntPtr handle, bool exactBitsOnly)
        {
            GetSystemInfo(out SystemInfo info);

            List<ulong> found = new();
            ulong address = (ulong)info.MinimumApplicationAddress.ToInt64();
            ulong maximum = (ulong)info.MaximumApplicationAddress.ToInt64();
            int structSize = Marshal.SizeOf<MemoryBasicInformation>();
            byte[]? buffer = null;

            while (address < maximum)
            {
                if (VirtualQueryEx(handle, (IntPtr)(long)address, out MemoryBasicInformation region,
                        (IntPtr)structSize) == IntPtr.Zero)
                    break;

                ulong regionSize = (ulong)region.RegionSize.ToInt64();
                if (regionSize == 0)
                    break;

                bool readable = region.State == MemCommit
                                && region.Type == MemPrivate
                                && (region.Protect & PageReadWrite) != 0
                                && (region.Protect & PageGuard) == 0;

                if (readable)
                {
                    ulong regionBase = (ulong)region.BaseAddress.ToInt64();
                    ulong offset = 0;

                    while (offset < regionSize)
                    {
                        int chunk = (int)Math.Min((ulong)MaxChunk, regionSize - offset);
                        if (buffer == null || buffer.Length < chunk)
                            buffer = new byte[chunk];

                        if (ReadProcessMemory(handle, (IntPtr)(long)(regionBase + offset), buffer,
                                (IntPtr)chunk, out IntPtr readBytes))
                        {
                            int count = (int)readBytes;

                            int start = (int)((8 - ((regionBase + offset) % 8)) % 8);

                            for (int i = start; i + 8 <= count; i += 8)
                            {
                                bool hit;
                                if (exactBitsOnly)
                                {
                                    hit = BitConverter.ToInt64(buffer, i) == LockedBits;
                                }
                                else
                                {
                                    double value = BitConverter.ToDouble(buffer, i);

                                    hit = Math.Abs(value - LockedFrameDelay) < FallbackTolerance;
                                }

                                if (hit)
                                {
                                    found.Add(regionBase + offset + (ulong)i);
                                    if (found.Count > MaxReasonableMatches)
                                        return found;
                                }
                            }
                        }

                        offset += (ulong)chunk;
                    }
                }

                address = (ulong)region.BaseAddress.ToInt64() + regionSize;
            }

            return found;
        }
    }
}
