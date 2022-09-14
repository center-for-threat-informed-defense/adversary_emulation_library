# README for User Execution of Macros

## Prerequisites

* OS: Windows 10
* Applications:
  * Microsoft Office 365
  * Office 2021 or other recent standalone versions of Office may work, but were
    not tested during development.
* Permissions:
  * You must be able to launch an Administrator instance of Powershell.
  * You must be able to configure permissions for macros in Office 365 settings
    (see below).
  * `winword.exe` (Microsoft Word) must be available in the Windows `Path` system
    environment variable.

### Prerequisites - Verify that `winword.exe` is on the Path

Open an instance of Powershell and run `winword.exe`. It should launch Microsoft
Word. If it does not, you probably need to add it to the `Path` system
environment variable. This is important because the `macro_doc.exe` executable
invokes `winword.exe` without specifying an absolute path, so it needs to be
possible to find `winword.exe` in the shell context. Adding it to the Path fixes
this.

### Prerequisites - Office Macro Settings

To enable macro execution in Microsoft Office, follow the instructions in
[Enable Macros in Microsoft Office](docs/enable_macros.md).

## Executing the Application

* The tool distribution contains a `build/` directory containing the files
  `macro_doc.exe` and `payloads/whoami.docm`.
* Open an Administrator instance of Powershell with the parent directory of that
  executable as the working directory.
* Execute it with no options to use `payloads\whoami.docm`:
  ```
  .\build\macro_doc.exe
  ```
* Execute it with another macro file by setting that file as the first argument:
  ```
  .\build\macro_doc.exe payloads\whoami.docm
  ```

This will open the specified document. You must close this document yourself.

## The Sample Macros

Source code for sample macros is included in the `payload_code\` directory.

* [whoami](payload_code/whoami.md)

> **Warning:** The Visual Basic code used in Microsoft Office differs a bit from
> regular Visual Basic; therefore the sample macros linked above may not run
> outside of a Word macro without modification.

## Creating and Editing Macro Documents

To insert the code in the sample macros into a new document or edit the example
macro documents in your archive, refer to [Create and Edit Macro
Documents](docs/create_macro_documents.md).
