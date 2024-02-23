tst_drv = executable('tst_drv', 'driver.c')

tst_srcs = [
	't1.c',
	't2.c',
	't3.c',
	't4.c',
	't5.c',
	't6.c',
	't7.c',
	't8.c',
]

libthread = dependency('threads')

foreach tst: tst_srcs
	t = executable(tst.split('.c')[0], tst, dependencies: libthread)
	test(tst, tst_drv, is_parallel: false, timeout: 30, depends: [exit0_exe, tst_drv], args: [exit0_exe.full_path(), t.full_path()])
endforeach

