# InfinityHook Library

Enables system call hooks, among other things, without disturbing PatchGuard. For more detail, see the original InfinityHook repository on [Github](https://github.com/everdox/InfinityHook). We utilize the `libinfinityhook` library.

## Compatibility

Known functional on Windows 10 v1903 or older. Tested on Build 17763.rs5_release.180914-1434 with test signing ON.

## Modifications

- Updated VS Project file `libinfinityhook.vcxproj` to incorporate into SnakeDriver, include Spectre Mitigation, and new Build targets
- Wrapped externs in `infinityhook.h` with `#ifdef __cplusplus` to improve compatibility
- Added SYSTEM_HANDLE_INFORMATION structure definitions to `ntint.h`
- Relocated `CkclSessionGuid` from `ntint.h` to `infinityhook.cpp`
