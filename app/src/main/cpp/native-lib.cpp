#include "logging.h"
#include "smap.h"
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
  std::string smap_detection = "No injection found using stats map";
  SoList::SoInfo *abnormal_soinfo = SoList::DetectInjection();
  VirtualMap::MapInfo *abnormal_vmap = VirtualMap::DetectInjection();
  /* StatsMap::SmapsEntry abnormal_smap = */
  /*     StatsMap::DetectInjection(std::string("libharfbuzz_ng.so")); */

  if (abnormal_soinfo != nullptr) {
    solist_detection =
        std::format("Solist: injection at {}", (void *)abnormal_soinfo);
    LOGE("Abnormal soinfo %p: %s loaded at %s", abnormal_soinfo,
         abnormal_soinfo->get_name(), abnormal_soinfo->get_path());
  }

  if (abnormal_vmap != nullptr) {
    vmap_detection =
        std::format("Virtual map: injection at {}", abnormal_vmap->path);
    LOGE("Abnormal vmap %s: [0x%lx-0x%lx]", abnormal_vmap->path.data(),
         abnormal_vmap->start, abnormal_vmap->end);
  }

  /* if (abnormal_smap.private_dirty_kb != -1) { */
  /*   smap_detection = */
  /*       std::format("Stats map: injection at {}", abnormal_smap.pathname); */
  /*   LOGE("Abnormal smap %s", abnormal_smap.pathname.data()); */
  /* } */

  return env->NewStringUTF(
      (solist_detection + "\n" + vmap_detection + "\n" + smap_detection)
          .c_str());
}
