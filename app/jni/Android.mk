LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dump
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/ElfFixSection/*.cpp)
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/ElfFixSection/*.c)
LOCAL_CFLAGS := -fvisibility=hidden -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CPPFLAGS	+= -frtti -fexceptions
LOCAL_LDLIBS += -llog

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := rev

#$(warning "the value of LOCAL_PATH is $(LOCAL_PATH)")

LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/ElfFixSection/*.cpp)
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/ElfFixSection/*.c)
LOCAL_SRC_FILES += $(LOCAL_PATH)/test.cpp

#$(warning "lc $(LOCAL_SRC_FILES)")

LOCAL_CFLAGS := -fvisibility=hidden -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CFLAGS := -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CPPFLAGS	+= -frtti -fexceptions
LOCAL_LDLIBS += -llog


include $(BUILD_SHARED_LIBRARY)
