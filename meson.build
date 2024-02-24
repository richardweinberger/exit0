project('inject-exit0', 'c')

if host_machine.system() != 'linux'
	error('Sorry, this tool works only on Linux.')
endif

add_global_arguments([
	'-D_GNU_SOURCE'
	],
	language: 'c'
)

exit0_exe = executable('exit0', 'exit0.c', install: true)

subdir('tests')
