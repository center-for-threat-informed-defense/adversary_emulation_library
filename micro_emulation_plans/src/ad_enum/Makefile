clean-build:
	if exist build\ad_enum.exe del build\ad_enum.exe
	if exist build\ad_enum.pdb del build\ad_enum.pdb

build-ad-enum:
	dotnet publish --configuration Release -p:PublishSingleFile=true -p:RuntimeIdentifier=win-x64 -o .\build

build-all: clean-build build-ad-enum