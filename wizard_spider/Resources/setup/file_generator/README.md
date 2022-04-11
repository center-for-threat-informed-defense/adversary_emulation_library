# File Generator
File generator used to populate a target machine with representative files. Uses
templates (supplied in the `templates` folder), currently covering the following
file types:
```
Text-based:
.doc, .docx, .rtf, .pdf

Presentations:
.ppt, .pptx

Spreadsheets:
.xls, .xlsx
```

Files are populated in the Documents and Desktop directories for each sub-directory 
in the initial target directory. Running the program requires root/administrator 
access to avoid issues with file distribution. Default file names are random per run and per folder.
If a seed value is provided, the folders will receive the same file names in every folder receiving a
distribution. This can be used to ensure exact scenario recreation on subsequent runs.

## User Options
```
-d, --directory         Path to the base directory in which to recurse. Defaults: C:\Users and /home

-t, --templatefolder    Path to the templates folder. Default: current working directory

-s, --seed              A seed value (string or int) to ensure file names are replicated exactly between runs/folders.

-c, --count             Total number of files to create. Files will be evenly spread. Default: 100

--noprompt              Suppress prompting for permission prior to creating needed directories
```

## Usage Examples
Example (executable co-located with templates, seed value of "EVALS", no prompts on folder creation):

`.\generate-files.exe -d "c:\test" -c 50 --seed "EVALS" --noprompt`

Example (Python file located away from templates, prompt prior to folder creation):

`python3 .\generate-files.py -d "c:\test" -t "c:\users\public\templates" -c 150`

## Creating a New Executable
While an executable has been supplied alongside the Python file, if you choose to make changes 
to the Python file (such as changing the file names or additional user folders to populate) and 
wish to re-compile it, install PyInstaller with pip:

`pip install pyinstaller`

You may need to add the installation directory to your PATH environment variable. In PowerShell:

`PS> $env:Path += ";<path to pyinstaller provided via pip>"`

Finally, compile the program with the `--console` flag to ensure output from the program.

`pyinstaller --onefile --console .\generate-files.py`

## User Tracking Information
Generated files currently will have one of the following names, followed by an underscore
and a random 6-character Alpha string. 
```
TEXT_FILE_NAMES = ['Report', 'Statistics', 'Analysis', 'Notes', 'Findings', 'Whitepaper']
PRESENTATION_FILE_NAMES = ['Quarterly Update', 'Roadmap', 'Master Schedule', 'Program Overview']
EXCEL_FILE_NAMES = ['Statistics', 'Budget', 'Staff Allocations', 'Inventory']
```

The program will provide console output regarding where, and how many, files were written.

Example output:
```
file_generator> python3 .\generate-files.py -d "c:\test" --noprompt --seed "EVALS"
[*] Using seed value: EVALS
[*] Prompt for directory creation: DISABLED
[*] Running on Windows
[OK] Running as Administrator
[OK] Using base directory: c:\test
[OK] Templates found
[*] Using the following file types (any others in the folder will be ignored):
        .doc .docx .rtf .pdf .ppt .pptx .xls .xlsx

[*] Beginning distribution
|--[*] Found 2 sub-directories in base path
|--[*] Obtained templates
|
|--[*] Using directory: c:\test\user1
|
|----[*] Looking for Desktop
|----[*] Desktop not found, attempting to create
|----[OK] Created directory: c:\test\user1\Desktop
|----[*] Copying files to c:\test\user1\Desktop
|----[OK] Wrote 25 files to directory
|
|----[*] Looking for Documents
|----[*] Documents not found, attempting to create
|----[OK] Created directory: c:\test\user1\Documents
|----[*] Copying files to c:\test\user1\Documents
|----[OK] Wrote 25 files to directory
|
|--[*] Using directory: c:\test\user2
|
|----[*] Looking for Desktop
|----[*] Desktop not found, attempting to create
|----[OK] Created directory: c:\test\user2\Desktop
|----[*] Copying files to c:\test\user2\Desktop
|----[OK] Wrote 25 files to directory
|
|----[*] Looking for Documents
|----[*] Documents not found, attempting to create
|----[OK] Created directory: c:\test\user2\Documents
|----[*] Copying files to c:\test\user2\Documents
|----[OK] Wrote 25 files to directory

[*] Program complete. Exiting.
```