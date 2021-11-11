#ifndef PYTHON_INJECT_INJECTOR_H
#define PYTHON_INJECT_INJECTOR_H

#include <ptrace/executor.h>
#include <list>
#include <vector>
#include <string>

class CInjector {
public:
    explicit CInjector(pid_t pid);
    ~CInjector();

public:
    bool open();

public:
    int inject(const std::string &library, bool file);

private:
    bool getAPIAddress(void **eval, void **ensure, void **release) const;

private:
    pid_t mPID;
    unsigned long mPageSize;

private:
    std::list<CExecutor *> mExecutors;
};


#endif //PYTHON_INJECT_INJECTOR_H
