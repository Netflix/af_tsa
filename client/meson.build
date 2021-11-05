project('af_tsa_client', 'c')

add_project_arguments('-Wall', language: 'c')
add_project_arguments('-Wuninitialized', language: 'c')
add_global_arguments('-g', language: 'c')
add_global_arguments('-ggdb3', language: 'c')

incdir = include_directories('../src')
sources = files(
	'client.c'
)
libmnl = dependency('libmnl')

client = executable(
	'client',
	sources,
	include_directories : incdir,
	dependencies: [libmnl],
	install: true,
)
