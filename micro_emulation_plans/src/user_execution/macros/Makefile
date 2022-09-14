DLL_PATH="./DLL/"
MACRO_EXE_NAME="macro_doc.exe"
MACRO_PDB_NAME="macro_doc.pdb"
MACRO_ARCHIVE="macro_doc.zip"
MACRO_ARCHIVE_EXE=$(MACRO_EXE_NAME)

clean-build-macro:
	if exist build\$(MACRO_EXE_NAME) del build\$(MACRO_EXE_NAME)
	if exist build\$(MACRO_PDB_NAME) del build\$(MACRO_PDB_NAME)
	if exist build\~.*.docm del 
	if exist bin del /q bin
	if exist obj del /q obj

build-macro:
	dotnet publish --configuration Release -p:PublishSingleFile=true -p:RuntimeIdentifier=win-x64 -o .\build

build-all-macro: clean-build-macro build-macro

clean-archive-macro:
	if exist $(MACRO_ARCHIVE) del $(MACRO_ARCHIVE)

build-archive-macro: clean-archive-macro
	zip $(MACRO_ARCHIVE) \
		build/$(MACRO_ARCHIVE_EXE) \
		payloads/*.docm \
		README_macros.md \
		docs/create_macro_docs/*.jpg \
		docs/create_macro_docs/*.png \
		docs/enable_macros/*.jpg \
		docs/enable_macros/*.png \
		docs/create_macro_documents.md \
		docs/enable_macros.md \
		payload_code/*.md