chmod 755 ./gen_cpio.sh
chmod 755 ./build.sh
chmod 755 ./extract-vmlinux
mkdir rootfs
cp *.cpio ./rootfs/rootfs.cpio
cd rootfs
cpio -idmv < rootfs.cpio
cd ..
mv ./gen_cpio.sh ./rootfs
echo "Init success!"
code exp.c

rm -rf init_*