clean-build:
	if exist build\iso.exe del build\iso.exe
	if exist build\iso.pdb del build\iso.pdb

build-iso:
	dotnet publish --configuration Release -p:PublishSingleFile=true -p:RuntimeIdentifier=win-x64 -o .\build

build-all: clean-build build-iso

clean-archive: 
	if exist bypass.zip del bypass.zip

archive: clean-archive
	zip -j bypass.zip \
		download.iso \
		build/iso.exe