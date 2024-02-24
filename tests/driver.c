#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char *exit0 = argv[1];
	char *tst = argv[2];
	pid_t tst_pid;
	int wstatus;

	assert(argc == 3);

	tst_pid = fork();

	/* Run test program. */
	if (tst_pid == 0) {
		char *tst_argv[2] = {tst, NULL};

		/*
		 * Make sure the test program terminates after 10 seconds.
		 */
		alarm(10);

		return execve(tst, tst_argv, NULL);
	}

	assert(tst_pid > 0);

	switch(fork()) {
		case 0: {
			/* Run exit0 on the test program. */

			char *exit0_argv[3] = { 0 };
			char *tst_pid_str;

			assert(asprintf(&tst_pid_str, "%i", tst_pid));

			exit0_argv[0] = exit0;
			exit0_argv[1] = tst_pid_str;
			/*
			 * Allow the test one second to establish.
			 */
			sleep(1);
			assert(execve(exit0, exit0_argv, NULL) != -1);
		}
		case -1:
			assert(0);
		default:
			/* Ensure test exits with code 0. */
			assert(waitpid(tst_pid, &wstatus, 0));
			assert(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0);
	}

	return 0;
}
