# elf-dump-fix
This resp include two utils

- dump  
  - Run on android, can dump elf from a process memory and fix it, Rebuild the Section Header for better IDA analysis,
- sofix
  - Run on PC, can fix an ELF file dumped from memory and an build the Section Header for better IDA analysis.
  
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

