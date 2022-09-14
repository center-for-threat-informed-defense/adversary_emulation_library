# Make targets for Windows.

GPLUSPLUS_PATH=C:\mingw64\bin\g++.exe
SERVER_EXE="namedpipes_server.exe"
CLIENT_EXE="namedpipes_client.exe"
EXECUTOR_EXE="namedpipes_executor.exe"

clean-build:
	if exist build\${CLIENT_EXE} del build\${CLIENT_EXE}
	if exist build\${EXECUTOR_EXE} del build\${EXECUTOR_EXE}
	if exist build\${SERVER_EXE} del build\${SERVER_EXE}

# Note: forward slashes can be used in g++ commands.
build-client:
	$(GPLUSPLUS_PATH) \
	-o build/${CLIENT_EXE} \
	src/namedpipes_client.cpp \
	-Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive \
	-static-libgcc \
	-static-libstdc++

build-server:
	$(GPLUSPLUS_PATH) \
	-o build/${SERVER_EXE} \
	src/namedpipes_server.cpp \
	-Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive \
	-static-libgcc \
	-static-libstdc++

build-executor:
	$(GPLUSPLUS_PATH) \
	-o build/${EXECUTOR_EXE} \
	src/namedpipes_executor.cpp \
	-Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive \
	-static-libgcc \
	-static-libstdc++

build-all: clean-build build-client build-server build-executor

clean-archive:
	if exist named_pipes.zip del named_pipes.zip

archive: clean-archive
	zip named_pipes.zip \
		README.md \
		BUILD.md \
		docs/*.* \
		build/${CLIENT_EXE} \
		build/${EXECUTOR_EXE} \
		build/${SERVER_EXE}
