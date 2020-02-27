# elf-dump-fix
This resp include two utils

- dump  
  - Run on android, can dump ELF from a process memory and fix it, Rebuild the Section Header for better IDA analysis.
- sofix
  - Run on PC, can fix an ELF file dumped from memory and an build the Section Header for better IDA analysis.

The main target is to rebuild the Section Header of an ELF by memory dumped.Useful in breaking packed so file like UPX or something like 360 libjiagu.so

## Build
 - dump
   - ```
     cd app/jni/
     ndk-build
      ```
   - output path is app/libs/armeabi-v7a/dump
   
 - sofix
   - on linux/mac, make sure clang/gcc is installed, just run ./build-fix.sh
   - on windows, It can be built in mingw , but not tested.
   
## HowToUse
 - sofix
   - params <src_so_path> <base_addr_in_memory_in_hex> <out_so_path>
     - <src_so_path> the elf file dumped from memory.
     - <base_addr_in_memory_in_hex> the memory base for the elf file dumped from memory, if you don't know, pass 0 is ok
     - <out_so_path> the output file
   - example
     - ./sofix dumped.so 0x6f5a4000 b.so
 - dump
   - This is run on Android Phone
   - make sure your phone have root access.
   - push it onto /data/local/tmp and grant +x like this
     - adb push app/libs/armeabi-v7a/dump /data/local/tmp/ && adb shell chmod 777 /data/local/tmp/dump
   - use adb shell to enter your phone and switch to root user by su command.
   - params <pid> <base_hex> <end_hex> <outPath> [is-stop-process-before-dump] [is-fix-so-after-dump]
     - <pid> the process id you want to dump
     - <base_hex> the start address of ELF you want to dump in process memory, you can get this by ```cat /proc/<pid>/maps```
     - <end_hex> the end address of ELF you want to dump in process memory, you can get this by ```cat /proc/<pid>/maps```
     - <outPath> the fixed ELF output path in your phone.
     - [is-stop-process-before-dump] 0/1 should send sigal to the process before doing dump job, useful in some anti dumping app. if there is no anti dumping on your target process, 0 is ok
     - [is-fix-so-after-dump] 0/1 should do the fix job and Section Header rebuilding, if you pass on, it will try to fix the ELF after dump.
   - example
     - if you want to dump libc.so, and your /proc/<pid>/maps like this
     - ```
         40105000-4014c000 r-xp 00000000 b3:19 717        /system/lib/libc.so
         4014c000-4014d000 ---p 00000000 00:00 0 
         4014d000-4014f000 r--p 00047000 b3:19 717        /system/lib/libc.so
         4014f000-40152000 rw-p 00049000 b3:19 717        /system/lib/libc.so
         40152000-40160000 rw-p 00000000 00:00 0 
        ```
     - ./dump 1148 0x40105000 0x40160000 ./out.so 0 1
       - dump to 40160000 not 40152000 is because the ELF .bss memory if exist should be dump too, the fix process depends on it.
  
## Compare between no-fix and fixed ELF
![](imgs/no-fix.png)
![](imgs/fix.png)

