#include "logging.h"
#include "solist.hpp"
#include "vmap.hpp"
#include <format>
#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_MainActivity_stringFromJNI(JNIEnv *env,
                                                jobject /* this */) {

  std::string solist_detection = "No injection found using solist";
  std::string vmap_detection = "No injection found using vitrual map";
  SoList::SoInfo *abnormal_soinfo = SoList::DetectInjection();
  VirtualMap::MapInfo *abnormal_map = VirtualMap::DetectInjection();
  if (abnormal_soinfo != nullptr) {
    solist_detection = std::format("Solist test: {}", (void *)abnormal_soinfo);
    LOGI("Abnormal soinfo %p: %s loaded at %s", abnormal_soinfo,
         abnormal_soinfo->get_name(), abnormal_soinfo->get_path());
  }

  if (abnormal_map != nullptr) {
    vmap_detection = std::format("Virtual map test: {}", abnormal_map->path);
    LOGI("Abnormal map %s: [0x%lx-0x%lx]", abnormal_map->path.data(),
         abnormal_map->start, abnormal_map->end);
  }

  return env->NewStringUTF((solist_detection + "\n" + vmap_detection).c_str());
}
