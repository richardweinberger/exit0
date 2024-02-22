# `exit0` - Terminate any program with exit code 0

Killing programs results into non-zero exit codes and monitoring/parent
processes will notice.
There are situations where you want to forcefully kill a program but
make it look like a graceful exit.

`exit0` offers this functionality, it stops all threads of a process
and implants into the main thread a syscall invocation of `exit_group(0)`.

Currently only AArch64 and x86_64 systems are supported.
Patches for more architectures and compat modes are welcome!
