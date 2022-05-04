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
using System.Linq;
using System.Net;

namespace SharpNP
{
    class NPDiscovery
    {
        public static List<uint> IPDiscovery()
        {
            // Initialize IP lists
            List<uint> arp_table = new List<uint>();
            List<uint> tcp_conns = new List<uint>();
            List<uint> all_ips = new List<uint>();

            try
            {
                // Get list of IPs using GetIpNetTable API 
                arp_table = SharpNP.ArpDiscovery.GetArpTable();
            }
            catch
            {
                Console.WriteLine("ARP enumeration failed");
            }

            all_ips = all_ips.Union(arp_table).ToList();

            try
            {
                // Get list of IPs using GetExtendedTcpTable API 
                tcp_conns = SharpNP.TcpConnDiscovery.GetAllTCPv4Ips();
            }
            catch
            {
                Console.WriteLine("TCP connection enumeration failed");
            }

            all_ips = all_ips.Union(tcp_conns).ToList();

            return TrimIpList(all_ips);
            //return all_ips;
        }

        public static List<uint> TrimIpList(List<uint> ipList)
        {
            // added .ToList(), which creates a copy of the original list
            foreach (var ip in ipList.ToList())
            {
                IPAddress addr = new IPAddress(ip);
                // Only target 10.0.1.8
                if (!addr.ToString().StartsWith("10.0.1.8"))
                {
                    ipList.Remove(ip);
                }

            }

            return ipList;
        }
    }
}
