# User Execution of ISO-Bypass

## Prerequisites

* OS: Windows 10
* Permissions:
  * You must be able to launch an instance of Powershell.

## Executing the Application

* The tool distribution contains a `build/` directory containing the files
  `iso.exe` and `download.iso`.
* Double-click `iso.exe` to mount the iso and execute the .bat file within:
  ```
  Command to execute: iso.exe -f download.iso
  ```
* For help with command line arguments, run `iso.exe -h`.

## Updating the iso file

### Prerequisites

* Windows 10
* Windows ADK ([Installation](https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install))

### Creating the ISO

* Create a folder named `download/`
* Add a new `.bat` file named `run.bat` in the `download/` folder
* Update the file to include any commands that you want the test to run
* Open the folder: `C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg`
* Run the command: `oscdimg -n -d -m PathToSource/download DestinationFolder/download.iso`
    * Replace PathToSource with the path to the `download` folder
    * Replace DestinationFolder with the location of the new `.iso` file
    * Example: `oscdimg -n -d -m E:\download E:\download.iso`
