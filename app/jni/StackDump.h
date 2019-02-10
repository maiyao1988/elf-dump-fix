//
// Created by 麦耀 on 2018/12/25.
//


#ifndef DUMPTEST_STACKDUMP_H
#define DUMPTEST_STACKDUMP_H

#include <stdint.h>
#include <unwind.h>
#include <dlfcn.h>
#include <android/log.h>

//为了不多余打印出堆栈，打堆栈的地方不能放函数里面，只能放在头文件
namespace {
    static void dumpBacktrace(void **buffer, size_t count, const char *tag) {
        for (size_t idx = 0; idx < count; ++idx) {
            const void *addr = buffer[idx];
            const char *symbol = "";
            const char *module = "";
            void *moduleBase = 0;

            Dl_info info;
            if (dladdr(addr, &info)) {
                if(info.dli_sname) {
                    symbol = info.dli_sname;
                }
                if (info.dli_fname) {
                    module =info.dli_fname;
                }
                moduleBase = info.dli_fbase;
            }

            //os << "  #" << std::setw(2) << idx << ": " << addr << "  " << symbol << "\n";
            __android_log_print(ANDROID_LOG_INFO, tag, "#%02d:%p %-70s %p %-10s", idx, addr, symbol, moduleBase, module);
        }
    }


    struct BacktraceState {
        void **current;
        void **end;
    };

    static _Unwind_Reason_Code unwindCallback(struct _Unwind_Context *context, void *arg) {
        BacktraceState *state = static_cast<BacktraceState *>(arg);
        uintptr_t pc = _Unwind_GetIP(context);
        if (pc) {
            if (state->current == state->end) {
                return _URC_END_OF_STACK;
            } else {
                *state->current++ = reinterpret_cast<void *>(pc);
            }
        }
        return _URC_NO_REASON;
    }
}

#define DUMP_CALL_STACK(tag) \
    const size_t ___max_ = 30; \
    void *___buffer_[___max_]; \
    BacktraceState ___state_ = {___buffer_, ___buffer_ + ___max_}; \
    _Unwind_Backtrace(unwindCallback, &___state_); \
    int ___count_ = ___state_.current - ___buffer_; \
    __android_log_print(ANDROID_LOG_INFO, tag, "call stack for [%s]:", __FUNCTION__); \
    dumpBacktrace(___buffer_, ___count_, tag);

#endif //DUMPTEST_STACKDUMP_H
