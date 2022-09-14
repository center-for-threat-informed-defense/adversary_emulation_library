clean-build:
	if exist build\FileAccess.exe del build\FileAccess.exe
	if exist build\FileAccess.pdb del build\FileAccess.pdb

build-FileAccess:
	dotnet publish --configuration Release -p:PublishSingleFile=true -p:RuntimeIdentifier=win-x64 -o .\build

build-all: clean-build build-FileAccess

clean-archive: 
	if exist FileAccess.zip del FileAccess.zip

archive: clean-archive
	zip FileAccess.zip \
		build/FileAccess.exe