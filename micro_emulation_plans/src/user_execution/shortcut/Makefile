clean-build:
	if exist build\generate_lnk.exe del build\generate_lnk.exe
	if exist build\generate_lnk.pdb del build\generate_lnk.pdb

build-gen-lnk:
	dotnet publish --configuration Release -p:PublishSingleFile=true -p:RuntimeIdentifier=win-x64 -o .\build

build-all: clean-build build-gen-lnk

clean-archive: if exist generate_lnk.zip del generate_lnk.zip

archive:
	zip generate_lnk.zip \
		build/generate_lnk.exe