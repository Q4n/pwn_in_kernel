chmod 755 ./gen_cpio.sh
chmod 755 ./build.sh
chmod 755 ./untils/extract-vmlinux
chmod 755 ./debug.sh
mkdir rootfs
cp *.cpio ./rootfs/rootfs.cpio.gz 
cd rootfs
gunzip rootfs.cpio.gz
cpio -idmv < rootfs.cpio
cd ..
mv ./gen_cpio.sh ./rootfs
mv ./debug.sh ./rootfs
echo "Init success!"
code exp.c

rm -rf init_*
