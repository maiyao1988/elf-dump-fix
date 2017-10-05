# FixElfSection
用于内存dump elf文件后的section修复，修复后可以在IDA中直接查看

内存dump具体方法为
dd if=/proc/<pid>/mem of=/sdcard/libxxx.so ibs=1 count=[size] skip=[skip]
其中[size]，[skip]分别为大小和首地址的十进制，可以从/proc/<pid>/maps中获取。
