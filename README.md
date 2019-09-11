# PWN_IN_KERNEL

kernel pwn中收集和自己写的一些脚本，方便exp开发

### USAGE: 

`unzip pwn_in_kernel.zip`

NOTICE：需要将startvm.sh(即启动脚本)中加载的fs改为rootfs.cpio

查看cpio的格式，是否进行gzip压缩
`file rootfs.cpio`

然后使用对应的init脚本初始化
`sh init_xxx.sh`

接着
```./build.sh```
```./startvm.sh```

即可开始你的表演