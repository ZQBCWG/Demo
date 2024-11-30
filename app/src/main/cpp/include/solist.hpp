#pragma once

#include "elf_util.h"
#include <string>

namespace SoList {
class SoInfo {
public:
#ifdef __LP64__
  inline static size_t solist_next_offset = 0x30;
  constexpr static size_t solist_realpath_offset = 0x1a8;
#else
  inline static size_t solist_next_offset = 0xa4;
  constexpr static size_t solist_realpath_offset = 0x174;
#endif

  inline static const char *(*get_realpath_sym)(SoInfo *) = NULL;
  inline static const char *(*get_soname_sym)(SoInfo *) = NULL;

  inline SoInfo *get_next() {
    return *(SoInfo **)((uintptr_t)this + solist_next_offset);
  }

  inline const char *get_path() {
    if (get_realpath_sym)
      return get_realpath_sym(this);

    return ((std::string *)((uintptr_t)this + solist_realpath_offset))->c_str();
  }

  inline const char *get_name() {
    if (get_soname_sym)
      return get_soname_sym(this);

    return ((std::string *)((uintptr_t)this + solist_realpath_offset -
                            sizeof(void *)))
        ->c_str();
  }

  void set_next(SoInfo *si) {
    *(SoInfo **)((uintptr_t)this + solist_next_offset) = si;
  }
};

class ProtectedDataGuard {
public:
  ProtectedDataGuard() {
    if (ctor != nullptr)
      (this->*ctor)();
  }

  ~ProtectedDataGuard() {
    if (dtor != nullptr)
      (this->*dtor)();
  }

  static bool setup(const SandHook::ElfImg &linker) {
    ctor = MemFunc{.data = {.p = reinterpret_cast<void *>(linker.getSymbAddress(
                                "__dl__ZN18ProtectedDataGuardC2Ev")),
                            .adj = 0}}
               .f;
    dtor = MemFunc{.data = {.p = reinterpret_cast<void *>(linker.getSymbAddress(
                                "__dl__ZN18ProtectedDataGuardD2Ev")),
                            .adj = 0}}
               .f;
    return ctor != nullptr && dtor != nullptr;
  }

  ProtectedDataGuard(const ProtectedDataGuard &) = delete;

  void operator=(const ProtectedDataGuard &) = delete;

private:
  using FuncType = void (ProtectedDataGuard::*)();

  static FuncType ctor;
  static FuncType dtor;

  union MemFunc {
    FuncType f;

    struct {
      void *p;
      std::ptrdiff_t adj;
    } data;
  };
};

static SoInfo *solist = NULL;
static SoInfo *somain = NULL;
static SoInfo **sonext = NULL;

static bool Initialize();

template <typename T>
inline T *getStaticPointer(const SandHook::ElfImg &linker, const char *name) {
  auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name));

  return addr == NULL ? NULL : *addr;
}

SoInfo *DetectInjection();

bool Initialize();

} // namespace SoList
