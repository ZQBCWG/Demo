# Detecting library injection in memory

## Detection using `solist`

In Bionic linker, the [soinfo](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h) structure has a [field next](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h;l=186), which points to the next loaded library in a linked list consisting of all loaded libraries.

Hence, an injected application can easily find all loaded libraries.

### Detection criteria

The following cases are considered as injections:
1. some `soinfo` object has empty pathname;
2. the linked list of all `soinfo` has gaps between elements, and such gap appears before [specializeAppProcess](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/com/android/internal/os/Zygote.java;l=436).

## Detection using `virtual maps`

See blog [Android 用户态注入隐藏已死](https://nullptr.icu/index.php/archives/182/).

## Detection using `mountinfo`

Current root solutions of Android are implemented in a systmeless way, meaning that they overlay the filesystems of the device by [mounting](https://man7.org/linux/man-pages/man8/mount.8.html) instead of overwriting the actual file contents.

The following cases are considered as injections:
1. common mount points of known root implementations present in [proc_pid_mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html);
2. gaps between mount IDs or mounting peer IDs appearing before mounting points specific to current application.


## Detection using `module counter`

A call to `dlclose` will increase the counter [g_module_unload_counter](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker.cpp;l=1956).

This detection highly depends on Android OS and vendor customization, which is shown to be false positive on Samsung and OnePlus.

# How to bypass all of them

Open source solution: [JingMatrix/NeoZygisk](https://github.com/JingMatrix/NeoZygisk) with [JingMatrix/APatch](https://github.com/JingMatrix/APatch).

