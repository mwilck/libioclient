kmod_dep = dependency('libkmod')

scsi_sources = ['kmod.c']
scsi_debug = shared_library('scsi',
			    scsi_sources,
			    include_directories: inc,
			    link_with: ioclib,
			    dependencies: kmod_dep,
			    install: false)
