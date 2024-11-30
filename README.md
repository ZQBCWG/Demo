# Detecting library injection in memory using `solist` and `virtual maps`

## Detection using `solist`

In Bionic linker, the [soinfo](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h) structure has a [field next](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h;l=186), which points to the next loaded library in a linked list consisting of all loaded libraries.

Hence, an injected application can easily find all loaded libraries.

### Detection criteria

The following cases are considered as injections:
1. some `soinfo` object has empty pathname;
2. the linked list of all `soinfo` has gaps between elements, and such gap appears before `libart.so` is loaded;
3. the library `libstats_jni.so` is not loaded exactly before the application's native library.

## Detection using `virtual maps`

See blog [Android 用户态注入隐藏已死](https://nullptr.icu/index.php/archives/182/).
