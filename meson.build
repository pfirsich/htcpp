project('httpserver', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])
threads = dependency('threads')

src = [
  'src/fd.cpp',
  'src/httpserver.cpp'
]
executable('httpserver', src, include_directories : ['src'],
  dependencies : [threads, liburingpp_dep])
