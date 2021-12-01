#ifndef PYTHON_INJECT_PAYLOAD_H
#define PYTHON_INJECT_PAYLOAD_H

#include "quit.h"
#include <stdbool.h>

typedef int (*PyRun_SimpleString)(const char *command);
typedef int (*PyGILState_Ensure)();
typedef void (*PyGILState_Release)(int state);

typedef struct {
    bool file;
    char script[1024];
    regs_t regs;
    PyRun_SimpleString eval;
    PyGILState_Ensure ensure;
    PyGILState_Release release;
} loader_payload_t;

#endif //PYTHON_INJECT_PAYLOAD_H
