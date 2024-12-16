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

## Detection using `module counter`

A call to `dlclose` will increase the counter [g_module_unload_counter](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker.cpp;l=1956).

## State of bypassing current test

- [ ] [Zygisk of Magisk](https://github.com/topjohnwu/Magisk)
- [ ] [ZygiskNext](https://github.com/Dr-TSNG/ZygiskNext)
- [x] [ReZygisk](https://github.com/PerformanC/ReZygisk) (fixed by JingMatrix in https://github.com/PerformanC/ReZygisk/pull/101)
