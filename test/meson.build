cmocka_dep = dependency('cmocka')

ioctest = executable('ioctest', 'ioctest.c',
		     include_directories : inc,
		     link_with : ioclib,
		     dependencies : [aio_dep, urcu_dep, thread_dep, rt_dep])

mocka_tests = {
		'log': false
	      }

foreach name, should_fail: mocka_tests
  # This searches the .c file for __wrap_xxx functions, and creates appropriate linker args
  # If any such functions are added, meson must be re-run
  r = run_command('sed', '-n', 's/^__wrap_\([a-zA-Z0-9_]*\).*$/-Wl,--wrap=\\1/p',
		  '@0@.c'.format(name))
  wrap = r.stdout().strip().split('\n')
  exe = executable(name, '@0@.c'.format(name),
		   include_directories : inc,
		   link_with: ioclib,
		   link_args: wrap,
		   dependencies : [cmocka_dep, aio_dep, urcu_dep, thread_dep, rt_dep])
  test(name, exe)
endforeach

