#include "logging.h"
#include "solist.hpp"
#include <format>
#include <jni.h>
#include <string>

using SoList::DetectInjection;

extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_MainActivity_stringFromJNI(JNIEnv *env,
                                                jobject /* this */) {

  std::string solist_detection = "No injection found through solist";
  SoList::SoInfo *abnormal_solist = DetectInjection();
  if (abnormal_solist != NULL) {
    solist_detection =
        std::format("Injection soinfo found at {}", (void *)abnormal_solist);
    LOGI("Recover record %p: %s loaded at %s", abnormal_solist,
         abnormal_solist->get_name(), abnormal_solist->get_path());
  }
  return env->NewStringUTF(solist_detection.c_str());
}
