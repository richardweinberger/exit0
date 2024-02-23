project('inject-exit0', 'c')

add_global_arguments([
	'-D_GNU_SOURCE'
	],
	language: 'c'
)

exit0_exe = executable('exit0', 'exit0.c', install: true)

subdir('tests')
