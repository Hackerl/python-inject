#ifndef PYTHON_INJECT_EXECUTOR_H
#define PYTHON_INJECT_EXECUTOR_H

#include "tracee.h"

enum emState {
    DETACHED,
    ATTACHED,
    TERMINATED
};

class CExecutor : public CTracee {
public:
    explicit CExecutor(pid_t pid);

public:
    bool run(const unsigned char *shellcode, unsigned int length, void *base, void *stack, void *argument, int &status);
    bool call(const unsigned char *shellcode, unsigned int length, void *base, void *stack, void *argument, void **result);

private:
    bool getExecBase(void **base) const;
};


#endif //PYTHON_INJECT_EXECUTOR_H
