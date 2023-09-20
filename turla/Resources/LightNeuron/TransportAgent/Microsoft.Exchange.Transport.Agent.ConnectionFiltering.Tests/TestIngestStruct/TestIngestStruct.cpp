#include "TestIngestStruct.h"

using namespace std;
namespace test_ingest_struct {

    extern "C" __declspec(dllexport) int MessageValidator(mail * s) {
        ofstream myfile;
        myfile.open("C:\\Windows\\serviceprofiles\\networkservice\\appdata\\Roaming\\Microsoft\\Windows\\TestIngestDebug");
        myfile << "Name: ";
        myfile << s->name << endl;
        myfile << "Total Recipients: ";
        myfile << s->totalRecipients << endl;
        myfile << "Recipients: " << endl;
        for (int i = 0; i < s->totalRecipients; i++) {
            char* r = *(s->recipients + i);
            myfile << r << endl;
        }
        myfile << "Total Attachments: ";
        myfile << s->totalAttachments << endl;
        myfile << "Attachment File Names: " << endl;
        for (int i = 0; i < s->totalAttachments; i++) {
            char* f = *(s->attachmentFileNames + i);
            myfile << f << endl;
        }
        myfile << "Attachment Contents: " << endl;
        for (int i = 0; i < s->totalAttachments; i++) {
            char* c = *(s->attachmentContents + i);
            myfile << c << endl;
        }
        myfile.close();

        // change this and recompile to test the different return values
        return 2;
    }
}