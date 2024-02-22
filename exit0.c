// SPDX-License-Identifier: GPL-2.0+
/*
 *  exit0 - Terminate any program with exit code 0
 * (c) 2024 - Richard Weinberger <richard@nod.at>
 */
#include <asm/unistd.h>
#include <assert.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

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

static void seize_thread(pid_t tid, int is_main)
{
	int wstatus;

	if (ptrace(PTRACE_SEIZE, tid, 0, 0) == -1) {
		/*
		 * Both ESRCH and EPERM can happen if a thread exits
		 * while we're trying to seize it.
		 */
		if ((errno == ESRCH || errno == EPERM) && !is_main)
			return;

		fprintf(stderr, "Unable to seize thread %i: %m\n", tid);
		exit(1);
	}

	ptrace_or_die(PTRACE_INTERRUPT, tid, 0, 0, "Unable to interrupt thread %i: %m\n", tid);

	if (wait4(tid, &wstatus, __WALL, NULL) == -1) {
		fprintf(stderr, "Unable to wait for thread %i: %m\n", tid);
		exit(1);
	}

	if (WIFSTOPPED(wstatus) == 0 && is_main) {
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
	ptrace_or_die(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov, "Unable to fetch registers of thread %i: %m\n",
		      tid);

	if (iov.iov_len != sizeof(uregs)) {
		fprintf(stderr, "Got not the amount of registers as expected.\n");
		fprintf(stderr, "Compat tasks are currently not supported.\n");
		exit(1);
	}

	pc = get_pc(&uregs);

	/*
	 * PTRACE_POKEDATA writes data word wise.
	 */
	for (i = 0; i < sizeof(syscall_asm) / sizeof(unsigned long); i++)
		ptrace_or_die(PTRACE_POKEDATA, tid, pc + i,
			      (void *)*((unsigned long *)syscall_asm + i),
			      "Unable to install code into thread %i: %m\n", tid);

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
	ptrace_or_die(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov, "Unable to restore registers of thread %i: %m\n",
		      tid);
	ptrace_or_die(PTRACE_CONT, tid, NULL, NULL, "Unable to continue thread %i: %m\n", tid);
}

static void seize_all_threads(pid_t pid)
{
	size_t seized_tids_sz = 32;
	pid_t *seized_tids;
	int seized_tids_cur = 0;
	struct dirent **tidlist;
	char *taskdir;
	int ntask, i, j;
	int verify = 0;
	int found_new_tids;

	if (asprintf(&taskdir, "/proc/%d/task/", pid) == -1) {
		fprintf(stderr, "Out of memory!\n");
		exit(1);
	}

	seized_tids = malloc(seized_tids_sz * sizeof(pid_t));
	if (seized_tids == NULL) {
		fprintf(stderr, "Out of memory!\n");
		exit(1);
	}

again:
	found_new_tids = 0;
	ntask = scandir(taskdir, &tidlist, NULL, alphasort);
	assert(ntask > 0);

	for (i = 0; i < ntask; i++) {
		struct dirent *e = tidlist[i];

		if (e->d_type != DT_DIR)
			goto skip_tid;

		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			goto skip_tid;

		/*
		 * We trust the kernel to not cheat on us.
		 */
		pid_t tid = atoi(e->d_name);
		assert(tid > 0);

		assert(seized_tids_cur <= seized_tids_sz);
		if (seized_tids_cur == seized_tids_sz) {
			seized_tids_sz *= 2;
			seized_tids = realloc(seized_tids, seized_tids_sz * sizeof(pid_t));
			if (seized_tids == NULL) {
				fprintf(stderr, "Out of memory!\n");
				exit(1);
			}
		}

		for (j = 0; j < seized_tids_cur; j++) {
			if (seized_tids[j] == tid)
				goto skip_tid;
		}

		seize_thread(tid, pid == tid);
		seized_tids[seized_tids_cur++] = tid;
		found_new_tids = 1;

skip_tid:
		free(e);
	}
	free(tidlist);

	if (found_new_tids) {
		if (verify++ > 10) {
			fprintf(stderr, "PID %i is creating faster new threads than I can scan!\n", pid);
			exit(1);
		}
		goto again;
	}

	free(taskdir);
	free(seized_tids);
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

	seize_all_threads(target_pid);
	implant_and_run_code(target_pid);

	return 0;
}
