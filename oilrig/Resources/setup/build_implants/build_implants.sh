#!/bin/sh

set -e

echo "Building SideTwist as SideTwist.exe..."
cd ../../SideTwist/SideTwist
x86_64-w64-mingw32-g++ -I include/ -static -std=c++14 -lstdc++fs -o bin/SideTwist.exe src/*.cpp -lwinhttp -lshlwapi -lucrt
strip -s bin/SideTwist.exe
RESULT=$?

echo "Building VALUEVAULT as b.exe..."
cd ../../VALUEVAULT
env GOOS=windows GOARCH=amd64 go build -mod vendor -trimpath -o b.exe -a main.go

echo "Staging VALUEVAULT (b.exe) in Resources/payloads/SideTwist..."
cp b.exe ../payloads/SideTwist

echo "Building RDAT as RDAT.exe..."
cd ../RDAT
dotnet publish -c Release -r win10-x64 -p:PublishSingleFile=true /p:DebugType=None /p:DebugSymbols=false

echo "Staging RDAT (RDAT.exe) in Resources/payloads/TwoFace..."
cp bin/Release/net6.0/win10-x64/publish/RDAT.exe ../payloads/TwoFace
