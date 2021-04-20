## AccountingIQ compilation instructions

### Install Choco
https://chocolatey.org/install

### Install Mingw
`choco install mingw --x86`

### Compile
`gcc -m32 .\AccountingIQ.c -o AccountingIQ.exe`

## pillowMint compilation instructions

### Install Choco
https://chocolatey.org/install

### Install Mingw
[ ! ] You may need to force install 64bit with `--x64 --force` if x86 was previously installed

`choco install mingw`

### Compile
`g++ -static pillowMint.cpp -o pillowMint.exe`
