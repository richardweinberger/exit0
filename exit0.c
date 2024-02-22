#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <asm/unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void ptrace_or_die(enum __ptrace_request request, pid_t tid, void *addr, void *data,
			  const char *err_fmt, ...)
{
	va_list ap;

	if (ptrace(request, tid, addr, data) == -1) {
		va_start(ap, err_fmt);
		vfprintf(stderr, err_fmt, ap);
		va_end(ap);
		exit(1);
	}
}

static void seize_thread(pid_t tid)
{
	int wstatus;

	ptrace_or_die(PTRACE_SEIZE, tid, 0, 0, "Unable to seize thread %i\n", tid);
	ptrace_or_die(PTRACE_INTERRUPT, tid, 0, 0, "Unable to interrupt thread %i\n", tid);

	if (wait4(tid, &wstatus, __WALL, NULL) == -1) {
		fprintf(stderr, "Unable to wait for thread %i\n", tid);
		exit(1);
	}

	if (WIFSTOPPED(wstatus) == 0) {
		fprintf(stderr, "Unexpected state for thread %i: %#x\n", tid, wstatus);
		exit(1);
	}
}

#ifdef __x86_64__
static unsigned char syscall_asm[] = {
	0x0f, 0x05, /* syscall */
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* nop */
};

static unsigned long *get_pc(struct user_regs_struct *uregs)
{
	/*
	 * Use the current page as memory for our new code.
	 * The code is less than page size, no need to allocate.
	 */
	return (unsigned long *)(uregs->rip & ~(PAGE_SIZE - 1));
}

static void set_pc(struct user_regs_struct *uregs, unsigned long *pc)
{
	uregs->rip = (unsigned long)pc;
}

static void setup_exit0(struct user_regs_struct *uregs)
{
	uregs->rax = __NR_exit_group;
	uregs->rdi = 0;
}

static void reset_syscall(struct user_regs_struct *uregs)
{
	uregs->orig_rax = -1;
}
#elif __aarch64__
static unsigned char syscall_asm[] = {
	0x01, 0x00, 0x00, 0xd4, /* svc #0 */
	0x1f, 0x20, 0x03, 0xd5, /* nop */
};

static unsigned long *get_pc(struct user_regs_struct *uregs)
{
	return (unsigned long *)(uregs->pc & ~(PAGE_SIZE - 1));
}

static void set_pc(struct user_regs_struct *uregs, unsigned long *pc)
{
	uregs->pc = (unsigned long)pc;
}

static void setup_exit0(struct user_regs_struct *uregs)
{
	uregs->regs[8] = __NR_exit_group;
	uregs->regs[0] = 0;
}

static void reset_syscall(struct user_regs_struct *uregs)
{
	// Not needed on ARM64
}
#else
#error "Sorry, your CPU architecture is currently not supported!"
#endif

static void implant_and_run_code(pid_t tid)
{
	struct user_regs_struct uregs;
	unsigned long *pc;
	struct iovec iov;
	int i;

	static_assert(sizeof(syscall_asm) % sizeof(unsigned long) == 0, "");
	static_assert(sizeof(syscall_asm) <= PAGE_SIZE, "");

	iov.iov_base = &uregs;
	iov.iov_len = sizeof(uregs);
	ptrace_or_die(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov, "Unable to fetch registers of thread %i\n",
		      tid);

	pc = get_pc(&uregs);

	for (i = 0; i < sizeof(syscall_asm) / sizeof(unsigned long); i++)
		ptrace_or_die(PTRACE_POKEDATA, tid, pc + i,
			      (void *)*((unsigned long *)syscall_asm + i),
			      "Unable to install code into thread %i\n", tid);

	/*
	 * If we interrupted the thread while executing a syscall
	 * we have to prevent it from restarting the syscall again.
	 * All we want it executing our freshly implanted code.
	 */
	reset_syscall(&uregs);

	set_pc(&uregs, pc);
	setup_exit0(&uregs);

	iov.iov_base = &uregs;
	iov.iov_len = sizeof(uregs);
	ptrace_or_die(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov, "Unable to restore registers of thread %i\n",
		      tid);
	ptrace_or_die(PTRACE_CONT, tid, NULL, NULL, "Unable to continue thread %i\n", tid);
}

int main(int argc, char **argv)
{
	int target_pid;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s PID\n", argv[0]);
		return 1;
	}

	target_pid = atoi(argv[1]);
	if (target_pid <= 0) {
		fprintf(stderr, "Bad PID %i\n", target_pid);
		return 1;
	}

	seize_thread(target_pid);
	implant_and_run_code(target_pid);

	return 0;
}
