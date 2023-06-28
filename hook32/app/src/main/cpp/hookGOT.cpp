
#include <dirent.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define LOG_TAG "HOOKGOT"

#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)

//#define LIBSF_PATH  "/data/app-lib/com.example.encript-1/libtest.so"
#define LIBSF_PATH  "/system/lib/libstdc++.so"

typedef int (*ptr_old_strcmp)(const char* c1, const char* c2) ;

ptr_old_strcmp old_strcmp = 0;

int new_strcmp(const char* c1, const char* c2)
{
    LOGD("[+]new_strcmp called [+]\n");
    LOGD("[+] s1 = %s [+]\n", c1);
    LOGD("[+] s2 = %s [+]\n", c2);
    if (old_strcmp == 0)
        LOGD("[+] error:old_strcmp = -1 [+]\n");
    return 0;
}







ssize_t readline(int fd, char *buffer, size_t n)
{
    ssize_t numRead;
    size_t totRead;
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL) {
        errno = EINVAL;
        return -1;
    }

    buf = (char*)buffer;

    totRead = 0;
    for (;;) {
        numRead = read(fd, &ch, 1);
        if (-1 == numRead) {
            if (errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        } else if (numRead == 0) {
            if (totRead == 0) {
                return 0;
            } else {
                break;
            }
        } else {
            if (totRead < n - 1) {
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n') {
                break;
            }
        }
    }

    *buf = '\0';

    return totRead;
}



void* get_module_base(pid_t pid, const char* module_name)
{
    int fd;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    int fp = open(filename, O_RDONLY);

    if (fp != NULL) {
        while (readline(fd,line,sizeof(line))) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        close(fd) ;
    }
    return (void *)addr;
}

int Hook(void* new_func,char* so_path,void* old_func)
{
    void* base_addr = NULL;

    Elf32_Shdr shdr;
    Elf32_Ehdr ehdr;
    unsigned long shdr_addr;
    int shnum;
    int shent_size;
    int i;
    unsigned long stridx;

    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0;
    int32_t got_found = 0;
    char * string_table = NULL;

    LOGD("[+]so path = %s [+]\n", so_path);
    if(so_path != NULL)
        base_addr = get_module_base(getpid(),so_path);
    LOGD("%s address = %p\n",so_path,base_addr);

    int fd = open(so_path, O_RDONLY);
    if (-1 == fd) {
        LOGD("[+] error: Open %s failed [+]\n",so_path);
        return -1;
    }

    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    shdr_addr = ehdr.e_shoff;
    shnum = ehdr.e_shnum;
    shent_size = ehdr.e_shentsize;
    stridx = ehdr.e_shstrndx;

    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(fd, &shdr, shent_size);

    string_table = (char *)malloc(shdr.sh_size);
    lseek(fd, shdr.sh_offset, SEEK_SET);
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);



    for (i = 0; i < shnum; i++) {
        read(fd, &shdr, shent_size);
        if (shdr.sh_type == SHT_PROGBITS) {
            int name_idx = shdr.sh_name;
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
                || strcmp(&(string_table[name_idx]), ".got") == 0) {
                out_addr = (uint32_t)base_addr + (uint32_t)shdr.sh_addr;
                out_size = shdr.sh_size;
                LOGD("[+] out_addr = %lx, out_size = %lx [+]\n", out_addr, out_size);

                for (i = 0; i < out_size; i += 4) {
//                  LOGD("loop\n");
                    got_item = *(uint32_t *)(out_addr + i);
                    if (got_item  == (uint32_t)old_func) {
                        LOGD("[+] Found target function in got[+]\n");
                        got_found = 1;

                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = (uint32_t)new_func;

                        break;
                    } else if (got_item == (uint32_t)new_func) {
                        LOGD("[+] Already hooked [+]\n");
                        break;
                    }
                }
                if (got_found)
                    break;
            }
        }
    }

    free(string_table);
    close(fd);

}




int main(){

    LOGD("Start hooking\n");

    Hook((void*)new_strcmp,(char*)LIBSF_PATH,(void*)strcmp);

    LOGD("Hook success\n");
    return 0;
}