# Setting up Dev Environment

Below are steps that will assist in setting up a macOS Catalina development environment.

- [Setting up Dev Environment](#setting-up-dev-environment)
  - [Use AWS macOS Virtual Machine for Development (remote)](#use-aws-macos-virtual-machine-for-development-remote)
  - [Use local Virtual Machine for Development (local)](#use-local-virtual-machine-for-development-local)
    - [Create a macOS Catalina Virtual Machine (local)](#create-a-macos-catalina-virtual-machine-local)
      - [How to Download the macOS Catalina Installer and Create an ISO File](#how-to-download-the-macos-catalina-installer-and-create-an-iso-file)
      - [Use the ISO to Create a Virtual Machine](#use-the-iso-to-create-a-virtual-machine)
  - [Install Xcode](#install-xcode)



## Use AWS macOS Virtual Machine for Development (remote)

Skip to [Install Xcode](#install-xcode) section.

## Use local Virtual Machine for Development (local)

Use the following section to create a local development virtual machine.

### Create a macOS Catalina Virtual Machine (local)

**NOTE**: You will need access to an x86/Intel system running macOS.

You will first need to create a macOS installer ISO, which will be used as the installer to create a virtual machine.

#### How to Download the macOS Catalina Installer and Create an ISO File

This process will take an installer for macOS and create an ISO file from it which can be booted or used as a typical disk image file.

1. First, [download the MacOS Catalina installer](https://itunes.apple.com/us/app/macos-catalina/id1466841314?ls=1&mt=12) from the Mac App Store, When the “Install MacOS Catalina.app” application is fully downloaded and within the /Applications folder, proceed to next step.
2. Open the Terminal application
3. Create a disk image DMG file by running the following command:

    `hdiutil create -o /tmp/Catalina -size 8500m -volname Catalina -layout SPUD -fs HFS+J`

4. Mount the created DMG disk image with the following command:

    `hdiutil attach /tmp/Catalina.dmg -noverify -mountpoint /Volumes/Catalina`

5. Use createinstallmedia to create the macOS installer application on the mounted volume:

    `sudo /Applications/Install\ macOS\ Catalina.app/Contents/Resources/createinstallmedia --volume /Volumes/Catalina --nointeraction`

6. When createinstallmedia has finished, unmount the volume you just created:

    `hdiutil detach /volumes/Install\ macOS\ Catalina`

7. Convert the DMG disk image file to an ISO disk image file (technically a CDR file, will rename in next step)

    `hdiutil convert /tmp/Catalina.dmg -format UDTO -o ~/Desktop/Catalina.cdr`

8. Finally, we rename the CDR file extension to ISO to convert the CDR to ISO:

    `mv ~/Desktop/Catalina.cdr ~/Desktop/Catalina.iso`

#### Use the ISO to Create a Virtual Machine

Follow the directions for your particular hypervisor to use the ISO to create and install macOS on a virtual machine. Directions for VMware and Parallels are listed below.

VMware Fusion: https://docs.vmware.com/en/VMware-Fusion/13/com.vmware.fusion.using.doc/GUID-474FC78E-4E77-42B7-A1C6-12C2F378C5B9.html

Parallels: https://kb.parallels.com/125374

## Install Xcode

First, download Xcode 12.4 from Apple. You will need a free Apple Developer account.

1. Download Xcode 12.4 from [Apple](https://developer.apple.com/download/all/?q=xcode%2012.4). 
   1. **NOTE**: Xcode 12.4 is the most recent release that supports macOS Catalina.
2. Extract the `xip` file by double clicking.
3. Move the Xcode.app file to the `/Applications` folder.
4. Launch `Xcode.app`.
5. Install Xcode Command Line Tools if necessary by running the following command in a Terminal window:
   1. `xcode-select --install`