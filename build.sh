gcc exp.c -static -O2 -masm=intel -o exp -lpthread -g
if [ $? -eq 0 ]; then   
    cd rootfs
    cp ../exp ./
    ./gen_cpio.sh ../rootfs.cpio
    cd ..
else
    echo "gcc error!"
fi