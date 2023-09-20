CALL "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" amd64
cmake --preset x64-debug
cmake --build ./build/x64-debug