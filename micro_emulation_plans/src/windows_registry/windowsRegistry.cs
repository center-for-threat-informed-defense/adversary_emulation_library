using System;
using System.Threading;
using System.Linq;
using System.Diagnostics;
using Microsoft.Win32;
class windowsRegistry {
	static void Main(string[] args) {
		string variance = "1";
		if (args.Length > 1) {
			Console.WriteLine("\nSupply only 1 argument:\n\n1 - API\n2 - Reg.exe\n3 - PowerShell.exe");
			System.Environment.Exit(1);
		}//end if
		else if (args.Length==0)
			variance = "1";
		else
			variance = args[0];
		switch (variance) {
			case "1":
				Console.WriteLine("\n=====API Variance=====");
				API();
				break;
			case "2":
				Console.WriteLine("\n=====Reg.exe Variance=====\n");
				Reg();
				break;
			case "3":
				Console.WriteLine("\n=====PowerShell.exe Variance=====");
				PowerShell();
				break;
			default:
				Console.WriteLine("\n=====API Variance=====");
				API();
				break;
		}//end switch
	}//end main
	public static void API() {
		RegistryKey key = Registry.CurrentUser.CreateSubKey("CTID");  
		key.SetValue("CTID", Environment.UserName + DateTime.Now);  
		Console.WriteLine("\nRegistry SubKey Created");
		Thread.Sleep(3000);
		Console.WriteLine("\nRegistry Path: " + key);
		Console.WriteLine("Registry Value: " + key.GetValue("CTID"));
		Thread.Sleep(3000);
		key.SetValue("CTID", System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Environment.UserName + DateTime.Now)));
		Console.WriteLine("\nUpdated Registry Value: " + key.GetValue("CTID"));
		Thread.Sleep(3000);
		Registry.CurrentUser.DeleteSubKeyTree("CTID");
		Console.WriteLine("\nRegistry SubKey Deleted");
		Thread.Sleep(3000);
	}//end API
	public static void Reg() {
		Process process = new Process();
		process.StartInfo.FileName = "reg.exe";
		process.StartInfo.RedirectStandardOutput = false;
		process.StartInfo.RedirectStandardError = false;
		process.StartInfo.UseShellExecute = false;
		process.StartInfo.Arguments = "ADD HKCU\\CTID /v CTID /t REG_SZ /d \"" + Environment.UserName + DateTime.Now + "\" /f";
		Console.WriteLine("\nCreating and Populating Registry SubKey");
		process.Start();
		Thread.Sleep(3000);
		process.StartInfo.Arguments = "QUERY HKCU\\CTID /v CTID";
		process.Start();
		Thread.Sleep(3000);
		Console.WriteLine("\nUpdating Registry Value");
		process.StartInfo.Arguments = "ADD HKCU\\CTID /v CTID /t REG_SZ /d \"" + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Environment.UserName + DateTime.Now)) + "\" /f";
		process.Start();
		Thread.Sleep(1000);
		process.StartInfo.Arguments = "QUERY HKCU\\CTID /v CTID";
		process.Start();
		Thread.Sleep(3000);
		Console.WriteLine("\nDeleting Registry SubKey");
		process.StartInfo.Arguments = "DELETE HKCU\\CTID /f";
		process.Start();
		Thread.Sleep(3000);
	}//end Reg
	public static void PowerShell() {
		Process process = new Process();
		process.StartInfo.FileName = "powershell.exe";
		process.StartInfo.RedirectStandardOutput = false;
		process.StartInfo.RedirectStandardError = false;
		process.StartInfo.UseShellExecute = false;
		process.StartInfo.Arguments = "-c New-Item -Force -Path \"HKCU:\\CTID\"; New-ItemProperty -Force -Path \"HKCU:\\CTID\" -Name \"CTID\" -PropertyType String -Value \'" + Environment.UserName + DateTime.Now + "\'";
		Console.WriteLine("\nCreating and Populating Registry SubKey");
		process.Start();
		Thread.Sleep(3000);
		Thread.Sleep(3000);
		Console.WriteLine("\nUpdating Registry Value");
		process.StartInfo.Arguments = "Set-ItemProperty -Force -Path \"HKCU:\\CTID\" -Name \"CTID\" -Value \'" + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Environment.UserName + DateTime.Now)) + "\'";
		process.Start();
		Thread.Sleep(1000);
		process.StartInfo.Arguments = "Get-ItemProperty -Path \"HKCU:\\CTID\" -Name \"CTID\"";
		process.Start();
		Thread.Sleep(3000);
		Console.WriteLine("\nDeleting Registry SubKey");
		process.StartInfo.Arguments = "Remove-Item -Path \"HKCU:\\CTID\" -Recurse";
		process.Start();
		Thread.Sleep(3000);	
	}//end PowerShell
}//end class