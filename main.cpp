#include "inject/injector.h"
#include <zero/log.h>
#include <zero/cmdline.h>

int main(int argc, char ** argv) {
    INIT_CONSOLE_LOG(zero::INFO);

    zero::CCmdline cmdline;

    cmdline.add({"pid", "process id", zero::value<int>()});
    cmdline.add({"script", "python script", zero::value<std::string>()});
    cmdline.addOptional({"file", 'f', "eval script from file", zero::value<bool>(), true});

    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");
    std::string script = cmdline.get<std::string>("script");
    bool file = cmdline.getOptional<bool>("file");

    LOG_INFO("eval %s", script.c_str());

    CInjector injector(pid);

    if (!injector.open()) {
        LOG_ERROR("process injector open failed");
        return -1;
    }

    return injector.inject(script, file);
}
