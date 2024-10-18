#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

#define SYSCALLS_LIST \
    (execve)(execveat)(open)(creat)(openat)(openat2)(readlink)(readlinkat)(lstat)(stat)(newfstatat)(faccessat)(faccessat2)(access)(unlinkat)(unlink)(rmdir)(rename)(renameat)(renameat2)(getdents)(getdents64)(chmod)(symlink)(symlinkat)(linkat)(link)(mkdir)(mkdirat)(utime)(utimes)(truncate)(newfstatat)

static void trace_child(pid_t child);
static void read_cstring(pid_t child, char *buffer, unsigned long address);
static void redirect_file(pid_t child, const char *file);

int main(int argc, char **argv)
{
    pid_t pid;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n", argv[0]);
        return 1;
    }

    if ((pid = fork()) == 0)
    {

        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

#define LOOP(seq) END(A seq)
#define BODY(name) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
                   BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE | (__NR_##name & SECCOMP_RET_DATA)),
#define A(x) BODY(x) B
#define B(x) BODY(x) A
#define A_END
#define B_END
#define END(...) END_(__VA_ARGS__)
#define END_(...) __VA_ARGS__##_END

            LOOP(SYSCALLS_LIST)

#undef LOOP
#undef BODY
#undef A
#undef B
#undef A_END
#undef B_END
#undef END

                BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        };

        struct sock_fprog prog = {
            .filter = filter,
            .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        };
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* To avoid the need for CAP_SYS_ADMIN */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
        {
            perror("when setting seccomp filter");
            return 1;
        }
        // kill(getpid(), SIGSTOP);
        raise(SIGSTOP);
        execvp(argv[1], argv + 1);
        if (errno)
        {
            perror("execvp");
            return 1;
        }
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL);
        trace_child(pid);
        return 0;
    }
}

static void trace_child(pid_t initial_pid)
{
    pid_t child = initial_pid;

    while (1)
    {
        printf("trace_child tracer pid: %d. tracee pid: %d\n", getpid(), child);
        char pathname[PATH_MAX];

        int status;

        ptrace(PTRACE_CONT, child, 0, 0);
        child = waitpid(child, &status, 0);
        printf("[child %d, status 0x%08x]\n", child, status);

        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)))
        {
            unsigned long msg;
            ptrace(PTRACE_GETEVENTMSG, child, 0, &msg);
            unsigned int syscall_nr = msg & SECCOMP_RET_DATA;

            printf("PID %d made syscall %d\n", child, syscall_nr);

            // get pid of the tracee

            switch (syscall_nr)
            {
            case __NR_openat:
                read_cstring(child, pathname, sizeof(long) * RSI);
                printf("[Opening %s]\n", pathname);

                break;

            case __NR_stat:
                read_cstring(child, pathname, sizeof(long) * RDI);
                printf("[Stat %s]\n", pathname);

                break;

            default:
                // printf("unhandled syscall\n");
                break;
            }
        }
        else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
        {
            int new_child;
            ptrace(PTRACE_GETEVENTMSG, child, 0, &new_child);
            printf("vfork %d\n", new_child);
            // ptrace(PTRACE_CONT, new_child, 0, 0);
            int new_status;
            waitpid(new_child, &new_status, 0);
            if (WIFSTOPPED(new_status))
            {
                printf("new child %d stopped\n", new_child);
                ptrace(PTRACE_CONT, new_child, 0, 0);
            }
            ptrace(PTRACE_CONT, child, 0, 0);
        }
        else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)))
        {
            // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG.
            int new_child;
            ptrace(PTRACE_GETEVENTMSG, child, 0, &new_child);
            printf("fork %d\n", new_child);
            int new_status;
            waitpid(new_child, &new_status, 0);
            if (WIFSTOPPED(new_status))
            {
                printf("new child %d stopped\n", new_child);
                ptrace(PTRACE_CONT, new_child, 0, 0);
            }
            ptrace(PTRACE_CONT, new_child, 0, 0);
            ptrace(PTRACE_CONT, child, 0, 0);
        }
        else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
        {
            int new_child;
            ptrace(PTRACE_GETEVENTMSG, child, 0, &new_child);
            printf("clone %d\n", new_child);
            ptrace(PTRACE_CONT, new_child, 0, 0);
            ptrace(PTRACE_CONT, child, 0, 0);
        }
        else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
        {
            printf("exec\n");
        }
        else if (WIFEXITED(status))
        {
            if (child == initial_pid)
            {
                // break;
            }
        }
        else
        {
            printf("tracer pid: %d. tracee pid: %d. status: 0x%08x\n", getpid(), child, status);
        }

        if (WIFEXITED(status))
        {
            // break;
        }

        /* Find out file and re-direct if it is the target */
    }
}

static void read_cstring(pid_t child, char *buffer, unsigned long address)
{
    char *child_addr;
    int i;

    child_addr = (char *)ptrace(PTRACE_PEEKUSER, child, address, 0);

    do
    {
        long val;
        char *p;

        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1)
        {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
            exit(1);
        }
        child_addr += sizeof(long);

        p = (char *)&val;
        for (i = 0; i < sizeof(long); ++i, ++buffer)
        {
            *buffer = *p++;
            if (*buffer == '\0')
                break;
        }
    } while (i == sizeof(long));
}

static void redirect_file(pid_t child, const char *file)
{
    char *stack_addr, *file_addr;

    stack_addr = (char *)ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSP, 0);
    /* Move further of red zone and make sure we have space for the file name */
    stack_addr -= 128 + PATH_MAX;
    file_addr = stack_addr;

    /* Write new file in lower part of the stack */
    do
    {
        int i;
        char val[sizeof(long)];

        for (i = 0; i < sizeof(long); ++i, ++file)
        {
            val[i] = *file;
            if (*file == '\0')
                break;
        }

        ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *)val);
        stack_addr += sizeof(long);
    } while (*file);

    /* Change argument to open */
    ptrace(PTRACE_POKEUSER, child, sizeof(long) * RSI, file_addr);
}