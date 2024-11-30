#include "solist.hpp"
#include <format>
#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_MainActivity_stringFromJNI(JNIEnv *env,
                                                jobject /* this */) {

  std::string result = "No injection found through solist";
  SoList::SoInfo *zygisk = SoList::DetectInjection();
  if (zygisk != NULL) {
    result = std::format("Injection soinfo found at {}", (void *)zygisk);
    LOGI("Recover record %p: %s loaded at %s", zygisk, zygisk->get_name(),
         zygisk->get_path());
  }
  return env->NewStringUTF(result.c_str());
}
