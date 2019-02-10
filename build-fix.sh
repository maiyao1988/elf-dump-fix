set -ex
DEBUG=$1
if [ "$DEBUG" = 1 ];then
	g++ main_fix.cpp app/jni/fix.cpp -O0 -g -o soFix
else
	g++ main_fix.cpp app/jni/fix.cpp -O2 -o soFix
fi
