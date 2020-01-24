ioc_sources = ['ioc.c']
ioclib = shared_library('ioclient',
			ioc_sources,
			include_directories : inc,
			dependencies : [aio_dep, urcu_dep, thread_dep, rt_dep],
			install : true)
