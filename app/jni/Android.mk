LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := dump
LOCAL_SRC_FILES := dump.cpp fix.cpp main.cpp
LOCAL_CFLAGS := -fvisibility=hidden -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CPPFLAGS	+= -frtti -fexceptions
LOCAL_LDLIBS += -llog

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
