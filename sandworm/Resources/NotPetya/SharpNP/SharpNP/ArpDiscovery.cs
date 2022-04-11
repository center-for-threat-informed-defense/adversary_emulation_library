/*=============================================================================================
*
*    Description:  This program emulates NotPetya.
*   
*        Version:  1.0
*        Created:  September 1st, 2021
*
*      Author(s):  Jesse Burgoon
*   Organization:  MITRE Engenuity
*
*  References(s): https://attack.mitre.org/software/S0368/
*
*=============================================================================================
*/
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

namespace SharpNP
{
    class ArpDiscovery
    {
        [DllImport("IpHlpApi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.U4)]
        static extern int GetIpNetTable(
            IntPtr pIpNetTable,
            [MarshalAs(UnmanagedType.U4)]
            ref int pdwSize,
            bool bOrder
        );

        // The insufficient buffer error.
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct MIB_IPNETROW
        {
            [MarshalAs(UnmanagedType.U4)]
            public int dwIndex;
            [MarshalAs(UnmanagedType.U4)]
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac0;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac1;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac2;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac3;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac4;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac5;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac6;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac7;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwAddr;
            [MarshalAs(UnmanagedType.U4)]
            public int dwType;
        }

        public static List<uint> GetArpTable()
        {
            // The number of bytes needed.
            int bytesNeeded = 0;

            // The result from the API call.
            int result = GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);

            // Call the function, expecting an insufficient buffer.
            if (result != ERROR_INSUFFICIENT_BUFFER)
            {
                // Throw an exception.
                throw new Win32Exception(result);
            }

            List<uint> arp_ips = new List<uint>();
            IntPtr buffer = Marshal.AllocHGlobal(bytesNeeded);

            try
            {
                // Make the call again. If it did not succeed, then raise an error.
                result = GetIpNetTable(buffer, ref bytesNeeded, false);
                // If the result is not 0 (no error), then throw an exception.
                if (result != 0)
                {
                    // Throw an exception.
                    throw new Win32Exception(result);
                }

                int entries = Marshal.ReadInt32(buffer);
                // Increment the memory pointer by the size of the int.
                IntPtr currentBuffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(typeof(int)));

                // Allocate an array of entries.
                MIB_IPNETROW[] table = new MIB_IPNETROW[entries];
                // Cycle through the entries.
                for (int index = 0; index < entries; index++)
                {
                    // Call PtrToStructure, getting the structure information.
                    table[index] = (MIB_IPNETROW)Marshal.PtrToStructure(new
                    IntPtr(currentBuffer.ToInt64() + (index *
                    Marshal.SizeOf(typeof(MIB_IPNETROW)))), typeof(MIB_IPNETROW));

                    // add each IP addr to the return variable
                    arp_ips.Add(table[index].dwAddr);
                }

            }
            finally 
            {
                Marshal.FreeHGlobal(buffer);
            }

            return arp_ips;
        }

    }
}
