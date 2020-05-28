project('libioc', 'c',
	version : '0.1.0',
        license : 'LGPL-2.1+',
	default_options : ['buildtype=debugoptimized',
			   'warning_level=2',
			   'c_std=gnu99'])

cc = meson.get_compiler('c')

add_global_arguments('-DMAX_LOGLEVEL=@0@'.format(get_option('max_loglevel')),
		     language: 'c')
if cc.has_argument('-Wno-clobbered')
   add_global_arguments(['-Wno-clobbered'], language: 'c')
endif

inc = include_directories('include')

urcu_dep = dependency('liburcu')
thread_dep = dependency('threads')
aio_dep = cc.find_library('aio')
rt_dep = cc.find_library('rt')

subdir('include')
subdir('src')
subdir('test')
