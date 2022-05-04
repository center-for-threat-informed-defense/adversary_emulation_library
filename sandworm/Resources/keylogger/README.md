# SetWindowsHookEx-Keylogger
Windows C++ Native Keylogger using SetWindowsHookEx

## Usage

The project solution can be compiled with the following commands (make file provided, compiles with g++)

```
cd sandworm\Resources\SetWindowsHookEx-Keylogger\src
make.bat
```

To run the executable in the background you can execute the binary in the background as follows

```
START /B "" SetWindowsHookEx-Keylogger.exe -o keylogger_output.txt
```

### Notes

Modifications to this project include:
- Write to file functionality (partially there with ofstream)
- Change solution configuration, and project structure
- Add BAT file to start the executable with `START /B "" SetWindowsHookEx-Keylogger.exe -o keylogger_output.txt`

### References
- Project based on: https://github.com/killswitch-GUI/SetWindowsHookEx-Keylogger/
- CTI Reference: https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
