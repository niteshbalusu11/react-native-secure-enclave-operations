#include <jni.h>
#include "secureenclaveoperationsOnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return margelo::nitro::secureenclaveoperations::initialize(vm);
}
