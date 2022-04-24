project('httpserver', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])
threads_dep = dependency('threads')

flags = []

src = [
  'src/config.cpp',
  'src/fd.cpp',
  'src/ioqueue.cpp',
  'src/log.cpp',
  'src/main.cpp',
  'src/server.cpp',
]

executable('httpserver', src, include_directories : ['src'],
  cpp_args : flags,
  dependencies : [threads_dep, liburingpp_dep])
