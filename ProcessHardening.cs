using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace HexiumLauncher
{

    internal static class ProcessHardening
    {
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = (IntPtr)0x00020007;

        private const ulong EXTENSION_POINT_DISABLE_ALWAYS_ON = 1UL << 32;

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFOW
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
            public int dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX
        {
            public STARTUPINFOW StartupInfo;
            public IntPtr lpAttributeList;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(
            string? lpApplicationName, StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static Process? Start(string exePath, string arguments, string workingDirectory,
                                     Action<string> log)
        {
            IntPtr attributeList = IntPtr.Zero;
            IntPtr policyPtr = IntPtr.Zero;
            try
            {
                var size = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                if (size == IntPtr.Zero)
                {
                    log("Process hardening unavailable: could not size the attribute list.");
                    return null;
                }

                attributeList = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref size))
                {
                    log("Process hardening unavailable: InitializeProcThreadAttributeList failed ("
                        + Marshal.GetLastWin32Error() + ").");
                    return null;
                }

                policyPtr = Marshal.AllocHGlobal(sizeof(ulong));
                Marshal.WriteInt64(policyPtr, unchecked((long)EXTENSION_POINT_DISABLE_ALWAYS_ON));

                if (!UpdateProcThreadAttribute(attributeList, 0,
                        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, policyPtr,
                        (IntPtr)sizeof(ulong), IntPtr.Zero, IntPtr.Zero))
                {
                    log("Process hardening unavailable: UpdateProcThreadAttribute failed ("
                        + Marshal.GetLastWin32Error() + ").");
                    return null;
                }

                var si = new STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
                si.lpAttributeList = attributeList;

                var commandLine = new StringBuilder("\"" + exePath + "\" " + arguments);

                if (!CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                        IntPtr.Zero, workingDirectory, ref si, out var pi))
                {
                    log("Process hardening unavailable: CreateProcessW failed ("
                        + Marshal.GetLastWin32Error() + ").");
                    return null;
                }

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);

                log("Client started with extension-point injection disabled (pid "
                    + pi.dwProcessId + ").");

                try
                {
                    return Process.GetProcessById(pi.dwProcessId);
                }
                catch (Exception)
                {

                    return null;
                }
            }
            catch (Exception ex)
            {
                log("Process hardening unavailable: " + ex.Message);
                return null;
            }
            finally
            {
                if (attributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (policyPtr != IntPtr.Zero) Marshal.FreeHGlobal(policyPtr);
            }
        }
    }
}
