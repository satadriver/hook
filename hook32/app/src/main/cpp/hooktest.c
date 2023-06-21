#include <stdio.h>
#include <errno.h>

#include "inlineHook.h"

int (*old_puts)(const char *) = NULL;

int new_puts(const char *string)
{
    return old_puts("inlineHook 32 success");
}

int hook()
{
    if (registerInlineHook((uint32_t) puts, (uint32_t) new_puts, (uint32_t **) &old_puts) != ELE7EN_OK) {
        printf("registerInlineHook error:%d\r\n",errno);
        return -1;
    }
    if (inlineHook((uint32_t) puts) != ELE7EN_OK) {
        printf("inlineHook error:%d\r\n",errno);
        return -1;
    }

    printf("hook ok\r\n");

    return 0;
}

int unHook()
{
    if (inlineUnHook((uint32_t) puts) != ELE7EN_OK) {
        printf("inlineUnHook error:%d\r\n",errno);
        return -1;
    }

    return 0;
}

int main()
{
    puts("test0");
    getchar();
    hook();
    puts("test1");
    getchar();
    unHook();
    puts("test2");
}