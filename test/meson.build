ioctest = executable('ioctest', 'ioctest.c',
		     include_directories : inc,
		     link_with : ioclib,
		     dependencies : [aio_dep, urcu_dep, thread_dep, rt_dep])
