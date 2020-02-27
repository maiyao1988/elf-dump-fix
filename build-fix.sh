set -ex
DEBUG=$1
if [ "$DEBUG" = 1 ];then
	g++ main_fix.cpp app/jni/ElfFixSection/fix.cpp -O0 -g -o sofix
else
	g++ main_fix.cpp app/jni/ElfFixSection/fix.cpp -O2 -o sofix
fi
