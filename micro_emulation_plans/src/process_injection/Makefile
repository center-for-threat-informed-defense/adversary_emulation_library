clean-build:
	if exist build\process_injection.exe del build\process_injection.exe
	if exist build\process_injection.pdb del build\process_injection.pdb

build-injection:
	dotnet publish --configuration Release -p:PublishSingleFile=true -p:RuntimeIdentifier=win-x64 -o .\build

build-all: clean-build build-injection