project('libioc', 'c',
	version : '0.1.0',
        license : 'LGPL-2.0+',
	default_options : ['buildtype=debugoptimized'])

cc = meson.get_compiler('c')

add_global_arguments(['-Wextra', '-Werror'], language: 'c')
if cc.has_argument('-Wno-clobbered')
   add_global_arguments(['-Wno-clobbered'], language: 'c')
endif

inc = include_directories('include')
urcu_dep = dependency('liburcu')
aio_dep = declare_dependency(link_args : '-laio')
thread_dep = dependency('threads')
rt_dep = cc.find_library('rt')
subdir('include')
subdir('src')
subdir('test')
