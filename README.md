# FixElfSection
用于内存中直接dump so文件，并自动修复。

dd if=/proc/[pid]/mem of=/sdcard/libxxx.so ibs=1 count=[size] skip=[skip]
其中[size]，[skip]分别为大小和首地址的十进制，可以从/proc/[pid]/maps中获取。
