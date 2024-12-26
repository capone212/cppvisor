
#include "syscalls.h"

#include <iostream>
#include <thread>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>


int execChild() {
    long result = ptrace(PTRACE_TRACEME, 0, 0, 0);
    std::cout << "Requested traceme permissions: " << result << std::endl;
    const char* args[] = {"/bin/bash", "-c", "echo Hello From Child!", 0};
    result = execve("/bin/bash", const_cast<char**>(args), nullptr);
    std::cerr << "execve failed on child with result:" << result << std::endl;
    return 0;
}

void checkError(long result) {
    if (result != 0) {
        throw std::runtime_error("Unexpected error: " + std::to_string(result));
    }
}

void tryPrintSysCallInfo(int childPid, int wstatus) {
    int isSysCall = WSTOPSIG(wstatus);
    if (isSysCall && 0x80 == 0) {
        std::cerr << "Is not a syscall" << std::endl;
        return;
    }

    user_regs_struct registers; 
    checkError(ptrace(PTRACE_GETREGS, childPid, 0, &registers));
    std::cerr << "syscall no: " << registers.orig_rax
        << " " << SYS_CALL_MAP.at(registers.orig_rax) << std::endl;
}

int execParent(int childPid) {
    // Wait for first stop before execve
    int wstatus = 0;
    int result = waitpid(childPid, &wstatus, 0);
    if (WIFSIGNALED(wstatus) || WIFEXITED(wstatus)) {
        std::cerr << "Child is unexpectedly terminated" << std::endl;
        return -1;
    }
    if (!WIFSTOPPED(wstatus)) {
        std::cerr << "Child is unexpected state: is not PTRACE_SYSCALL no stopped by signal" << std::endl;
        return -1;
    }
    std::cout << "Waited for initial child stop." << std::endl;
    checkError(ptrace(PTRACE_SETOPTIONS, childPid, 0, PTRACE_O_TRACESYSGOOD));

    while (!WIFSIGNALED(wstatus) && !WIFEXITED(wstatus)) {
        if (WIFSTOPPED(wstatus)) {
            tryPrintSysCallInfo(childPid, wstatus);
            checkError(ptrace(PTRACE_SYSCALL, childPid, 0, 0));
        } else {
            std::cerr << "Status is not stopped nor exited: " << wstatus << std::endl;
        }
        result = waitpid(childPid, &wstatus, 0);
    }

    return 0;
}

int doFork() {
    int childPid = fork();
    if (childPid < 0) {
        std::cerr << "Fork failed!" << std::endl;
        return -1;
    }

    if (childPid == 0) {
        return execChild();
    } else {
        return execParent(childPid);
    }

    return 0;
}

int main() {
    return doFork();
}
