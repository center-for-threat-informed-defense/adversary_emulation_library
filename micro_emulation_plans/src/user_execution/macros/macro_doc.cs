using System;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;

public struct PROCESS_INFORMATION {
	public IntPtr hProcess;
	public IntPtr hThread;
	public uint dwProcessId;
	public uint dwThreadId;
}//end struct
public struct STARTUPINFO {
	public uint cb;
	public string lpReserved;
	public string lpDesktop;
	public string lpTitle;
	public uint dwX;
	public uint dwY;
	public uint dwXSize;
	public uint dwYSize;
	public uint dwXCountChars;
	public uint dwYCountChars;
	public uint dwFillAttribute;
	public uint dwFlags;
	public short wShowWindow;
	public short cbReserved2;
	public IntPtr lpReserved2;
	public IntPtr hStdInput;
	public IntPtr hStdOutput;
	public IntPtr hStdError;
}//end struct
public struct SECURITY_ATTRIBUTES {
	public int length;
	public IntPtr lpSecurityDescriptor;
	public bool bInheritHandle;
}//end struct

class MacroMaker{

	[DllImport("kernel32.dll")]
	static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
		bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
		string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,out PROCESS_INFORMATION lpProcessInformation);

    static void Main(string[] args) {
		Console.Clear();
		string macro_doc_path = "..\\payloads\\whoami.docm";
		if (args.Length == 1) {
			// Get the full path.
			macro_doc_path = System.IO.Path.GetFullPath(args[0]);
		} else if (args.Length == 0) {
			Console.WriteLine("No macro document path specified. Using default.\n");
		}
		Console.WriteLine("Will open:\n\t" + macro_doc_path + "\n");
		Console.WriteLine("The user must close the document on their own when finished.\n");
		try {
			Process currentProcess = Process.GetCurrentProcess();
			Process process = new Process();
			process.StartInfo.FileName = "winword.exe";
			process.StartInfo.Arguments = macro_doc_path;
			process.StartInfo.RedirectStandardOutput = true;
			process.StartInfo.RedirectStandardError = true;
			process.StartInfo.UseShellExecute = false;
			process.Start();
			Console.WriteLine(process.ProcessName + " started at " + process.StartTime + " as PID " + process.Id);
			//find real winword.exe
			Thread.Sleep(1000);
			Console.Write("\nPress enter to continue ");
			Console.ReadLine();
			// File.Delete(path);
			Console.WriteLine("This program will now exit.");
		}//end try
		catch (Exception ex) {
			Console.Write(ex + "\n\nAlso double check that you have enabled macros and automagic code access (aka trust access to the VBA project object model) for this jazz to work\n\nPeep https://support.office.com/en-us/article/enable-or-disable-macros-in-office-files-12b036fd-d140-4e74-b45e-16fed1a7e5c6 for the good word\n");
			Console.WriteLine("This program will now exit.");
		}//end catch
    }//end Main
}
