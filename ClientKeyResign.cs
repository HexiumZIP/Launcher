using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HexiumLauncher
{

    internal static class ClientKeyResign
    {
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOACCESS = 0x01;

        private static readonly string[] UpstreamKeyPrefixes =
        {
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsI9zRp2OSccqdFx2",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAupANB3EbN9hFHHUj",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzjPRQo9jc/DsEVxo",
        };

        private const string HexiumKeyBlock =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz0IILqUPdihAVc7fiz3d\n" +
            "KjOuHe5swF37bNi83hyEetamTtnvNrT9f2c8gNAH9ONPIbWIknd4eCnM3jf/MsW9\n" +
            "msVXCO19UC68AequZ6lEjfOOPfPjHM1rFUGb9/kT1gWlMewoXkg2h6oDo+oFI5QL\n" +
            "oLKVRAF+3Dn1KBO4Y7fIDS1xNLpPBQeG7JW8tlZkduK0ZkRWy6LXTS/AhPYTxyzY\n" +
            "06ztC7SV26vKUmhypasvIC4kOBnC+O0fH/3blpEIWT6He2vY+kIUd8AFge+fMcsn\n" +
            "lv78eF2GSFQBZrxla1NoUm+OigwfaOwvmLBdHeLxhom9mrW8GqQq3OiWsI9ssp27\n" +
            "8QIDAQAB\n" +
            "-----END PUBLIC KEY-----";

        private static readonly byte[] BeginMarker = Encoding.ASCII.GetBytes("-----BEGIN PUBLIC KEY-----");

        private static readonly byte[] PlaceIdVerifySignature =
        {
            0x8D, 0x8D, 0xD4, 0xFD, 0xFF, 0xFF,
            0xE8, 0x8F, 0x6E, 0xFF, 0xFF,
            0x84, 0xC0,
            0x74, 0x5A
        };
        private static readonly byte[] PlaceIdVerifyPatch = { 0x90, 0x90 };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MemoryBasicInformation buffer, IntPtr length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, IntPtr size, out IntPtr read);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, IntPtr size, out IntPtr written);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr process, IntPtr address, IntPtr size, uint newProtect, out uint oldProtect);

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryBasicInformation
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public static void StartAsync(int processId, string clientVersion, Action<string> log)
        {
            if (processId <= 0) return;
            if (clientVersion == null || clientVersion.IndexOf("2021", StringComparison.OrdinalIgnoreCase) < 0)
                return;
            _ = Task.Run(() =>
            {
                try { Run(processId, log); }
                catch (Exception ex) { log?.Invoke($"[KeyResign] non-fatal: {ex.Message}"); }
            });
        }

        private static void Run(int processId, Action<string> log)
        {
            byte[] hexBlock = Encoding.ASCII.GetBytes(HexiumKeyBlock);
            byte[][] prefixes = new byte[UpstreamKeyPrefixes.Length][];
            for (int i = 0; i < prefixes.Length; i++)
                prefixes[i] = Encoding.ASCII.GetBytes(UpstreamKeyPrefixes[i]);

            IntPtr handle = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                false, processId);
            if (handle == IntPtr.Zero) { log?.Invoke("[KeyResign] OpenProcess failed"); return; }

            try
            {
                var done = new HashSet<int>();
                var placeIdDone = new bool[1];
                int[] delays = { 1500, 2000, 2500, 3000, 4000, 5000 };
                foreach (int delay in delays)
                {
                    Thread.Sleep(delay);
                    ScanAndPatch(handle, prefixes, hexBlock, done, placeIdDone, log);
                    if (done.Count == prefixes.Length)
                    {
                        log?.Invoke($"[KeyResign] all {done.Count} client keys re-signed to Hexium");
                        return;
                    }
                }

                if (done.Count > 0) log?.Invoke($"[KeyResign] re-signed {done.Count}/{prefixes.Length} client keys");
                else log?.Invoke("[KeyResign] client keys not found");
            }
            finally { CloseHandle(handle); }
        }

        private static bool ScanAndPatch(IntPtr handle, byte[][] prefixes, byte[] hexBlock, HashSet<int> done, bool[] placeIdDone, Action<string> log)
        {
            bool any = false;
            ulong address = 0x10000, max = 0x7FFF0000;
            int mbiSize = Marshal.SizeOf(typeof(MemoryBasicInformation));
            byte[] window = null;

            while (address < max)
            {
                if (VirtualQueryEx(handle, (IntPtr)(long)address, out MemoryBasicInformation region, (IntPtr)mbiSize) == IntPtr.Zero)
                    break;
                ulong regionBase = (ulong)region.BaseAddress.ToInt64();
                ulong regionSize = (ulong)region.RegionSize.ToInt64();
                if (regionSize == 0) break;

                bool readable = region.State == MEM_COMMIT
                    && (region.Protect & PAGE_GUARD) == 0
                    && (region.Protect & PAGE_NOACCESS) == 0;

                if (readable && regionSize <= 64UL * 1024 * 1024)
                {
                    if (window == null || window.Length < (int)regionSize)
                        window = new byte[(int)regionSize];
                    if (ReadProcessMemory(handle, region.BaseAddress, window, (IntPtr)(long)regionSize, out IntPtr read) && (long)read > 0)
                    {
                        int len = (int)read;

                        if (false && !placeIdDone[0])
                        {
                            int pat = IndexOf(window, PlaceIdVerifySignature, len);
                            if (pat >= 0)
                            {

                                ulong bva = regionBase + (ulong)(pat + PlaceIdVerifySignature.Length - 2);
                                if (Patch(handle, (IntPtr)(long)bva, PlaceIdVerifyPatch, log))
                                {
                                    placeIdDone[0] = true; any = true;
                                    log?.Invoke($"[KeyResign] PlaceId check @ {bva:X} -> nop");
                                }
                            }
                        }

                        for (int k = 0; k < prefixes.Length; k++)
                        {
                            if (done.Contains(k)) continue;
                            int at = IndexOf(window, prefixes[k], len);
                            if (at < 0) continue;
                            int begin = LastIndexOf(window, BeginMarker, at);
                            if (begin < 0) continue;
                            ulong va = regionBase + (ulong)begin;
                            if (Patch(handle, (IntPtr)(long)va, hexBlock, log))
                            {
                                done.Add(k); any = true;
                                log?.Invoke($"[KeyResign] key {k} @ {va:X} -> Hexium");
                            }
                        }
                    }
                }
                address = regionBase + regionSize;
            }
            return any;
        }

        private static bool Patch(IntPtr handle, IntPtr address, byte[] data, Action<string> log)
        {
            if (!VirtualProtectEx(handle, address, (IntPtr)data.Length, PAGE_READWRITE, out uint old))
                return false;
            bool ok = WriteProcessMemory(handle, address, data, (IntPtr)data.Length, out _);
            VirtualProtectEx(handle, address, (IntPtr)data.Length, old, out _);
            return ok;
        }

        private static int IndexOf(byte[] hay, byte[] needle, int hayLen)
        {
            int end = hayLen - needle.Length;
            for (int i = 0; i <= end; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        private static int LastIndexOf(byte[] hay, byte[] needle, int from)
        {
            for (int i = Math.Min(from, hay.Length - needle.Length); i >= 0; i--)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }
    }
}
