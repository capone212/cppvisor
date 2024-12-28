
#include "syscalls.h"

#include <iostream>
#include <thread>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <optional>


int execChild() {
    long result = ptrace(PTRACE_TRACEME, 0, 0, 0);
    std::cout << "Requested traceme permissions: " << result << std::endl;
    const char* args[] = {"/bin/bash", "-c", "echo Hello From Child!", 0};
    result = execve("/bin/bash", const_cast<char**>(args), nullptr);
    std::cerr << "execve failed on child with result:" << result << std::endl;
    return 0;
}

auto checkError(auto result) {
    if (result != 0) {
        throw std::runtime_error("Unexpected error: " + std::to_string(result));
    }
    return result;
}

constexpr int SYS_CALL_WRITE = 1;
constexpr int SYS_STDOUT = 1;

static int lastWriteSize = 0;

void handleConsoleWriteEnter(int childPid, user_regs_struct& registers) {
    auto dataAddress = registers.rsi;
    int count = registers.rdx;
    std::string buffer;

    while (count > 0) {
        std::cout << "Reading count: " << count << " from address: " << dataAddress << std::endl;
        errno = 0;
        std::uint64_t data = ptrace(PTRACE_PEEKDATA, childPid, dataAddress, 0);
        if (data == -1 && errno != 0) {
            throw std::runtime_error("Reading memory is failed!");
        }

        int readCount = std::min(count, 8);
        count -= readCount;
        dataAddress += readCount;
        const auto* begin = reinterpret_cast<char*>(&data);
        buffer.append(begin, readCount);
    }

    std::cout << "Intercepted out buffer: " << buffer << std::endl;
    lastWriteSize = registers.rdx;
    registers.rdx = 0;
    registers.rsi = 0;
    checkError(ptrace(PTRACE_SETREGS, childPid, 0, &registers));
}

void handleConsoleWriteExit(int childPid, user_regs_struct& registers) {
    registers.rax = lastWriteSize;
    lastWriteSize = 0;
    checkError(ptrace(PTRACE_SETREGS, childPid, 0, &registers));
}

void tryPrintSysCallInfo(int childPid, int wstatus, std::optional<std::uint64_t>& lastSysCall) {
    int isSysCall = WSTOPSIG(wstatus);
    if (isSysCall && 0x80 == 0) {
        std::cerr << "Is not a syscall" << std::endl;
        return;
    }

    user_regs_struct registers; 
    checkError(ptrace(PTRACE_GETREGS, childPid, 0, &registers));

    bool sysExit = lastSysCall == registers.orig_rax;

    std::cerr << "syscall no: " << registers.orig_rax
        << " " << SYS_CALL_MAP.at(registers.orig_rax)
        << " sysexit: " << sysExit << std::endl;

    if (registers.orig_rax == SYS_CALL_WRITE && registers.rdi == SYS_STDOUT) {
        if (sysExit) {
            handleConsoleWriteExit(childPid, registers);
        } else {
            handleConsoleWriteEnter(childPid, registers);
        }
    }

    if (sysExit) {
        lastSysCall.reset();
    } else {
        lastSysCall = registers.orig_rax;
    }
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

    std::optional<std::uint64_t> lastSysCall;

    while (!WIFSIGNALED(wstatus) && !WIFEXITED(wstatus)) {
        if (WIFSTOPPED(wstatus)) {
            tryPrintSysCallInfo(childPid, wstatus, lastSysCall);
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
