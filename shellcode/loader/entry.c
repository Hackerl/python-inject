#include "payload.h"
#include <z_log.h>
#include <z_syscall.h>
#include <z_memory.h>
#include <fcntl.h>

void main(void *ptr) {
    loader_payload_t *payload = (loader_payload_t *)ptr;

    if (!payload->file) {
        LOG("eval: %s", payload->script);

        int state = payload->ensure();

        if (payload->eval(payload->script) != 0) {
            payload->release(state);
            z_exit(-1);
        }

        payload->release(state);
        z_exit(0);
    }

    LOG("eval script: %s", payload->script);

    int fd = Z_RESULT_V(z_open(payload->script, O_RDONLY, 0));

    if (fd < 0) {
        LOG("open script failed: %s", payload->script);
        z_exit(-1);
    }

    long fs = Z_RESULT_V(z_lseek(fd, 0, SEEK_END));

    if (fs < 0) {
        z_close(fd);
        z_exit(-1);
    }

    if (Z_RESULT_V(z_lseek(fd, 0, SEEK_SET)) < 0) {
        z_close(fd);
        z_exit(-1);
    }

    char *buffer = z_calloc(fs + 1, 1);

    if (!buffer) {
        z_close(fd);
        z_exit(-1);
    }

    if (Z_RESULT_V(z_read(fd, buffer, fs)) != fs) {
        z_free(buffer);
        z_close(fd);
        z_exit(-1);
    }

    z_close(fd);

    int state = payload->ensure();

    if (payload->eval(buffer) != 0) {
        payload->release(state);
        z_free(buffer);
        z_exit(-1);
    }

    payload->release(state);

    z_free(buffer);
    z_exit(0);
}

#if __i386__ || __x86_64__

__asm__ (
".section .entry;"
".global entry;"
"entry:"
"    nop;"
"    nop;"
"    call main;"
"    int3"
);

#elif __arm__

__asm__ (
".section .entry;"
".global entry;"
"entry:"
"    nop;"
"    bl main;"
"    .inst 0xe7f001f0"
);

#elif __aarch64__

__asm__ (
".section .entry;"
".global entry;"
"entry:"
"    nop;"
"    bl main;"
"    .inst 0xd4200000"
);

#else
#error "unknown arch"
#endif
