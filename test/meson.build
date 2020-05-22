cmocka_dep = dependency('cmocka')
kmod_dep = dependency('libkmod')

scsi_sources = ['scsi.c']
scsi = shared_library('scsi',
		      scsi_sources,
		      include_directories: inc,
		      link_with: ioclib,
		      dependencies: kmod_dep,
		      install: false)

ioctest = executable('ioctest', 'ioctest.c',
		     include_directories : inc,
		     link_with : ioclib,
		     dependencies : [aio_dep, urcu_dep, thread_dep, rt_dep])

mocka_tests = {
		'log': {},
		'scsi_debug': {
				'src': ['scsi.c'],
				'deps': kmod_dep
			      },
	      }

foreach name, properties: mocka_tests
  # This searches the .c file for __wrap_xxx functions, and creates appropriate linker args
  # If any such functions are added, meson must be re-run
  r = run_command('sed', '-n', 's/^__wrap_\([a-zA-Z0-9_]*\).*$/-Wl,--wrap=\\1/p',
		  '@0@.c'.format(name))
  wrap = r.stdout().strip().split('\n')
  src = ['@0@.c'.format(name)]
  if 'src' in properties
    src += properties['src']
  endif
  link = [ioclib]
  if 'lib' in properties
       link = properties['lib'] + link
  endif
  deps = [cmocka_dep, aio_dep, urcu_dep, thread_dep, rt_dep]
  if 'deps' in properties
    deps += properties['deps']
  endif
  exe = executable(name, src,
		   include_directories : inc,
		   link_with: link,
		   link_args: wrap,
		   dependencies : deps)
  test(name, exe)
endforeach
