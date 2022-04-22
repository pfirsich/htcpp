project('httpserver', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])
threads = dependency('threads')

src = [
  'src/config.cpp',
  'src/fd.cpp',
  'src/filecache.cpp',
  'src/filewatcher.cpp',
  'src/http.cpp',
  'src/ioqueue.cpp',
  'src/main.cpp',
  'src/router.cpp',
  'src/server.cpp',
  'src/string.cpp',
]
executable('httpserver', src, include_directories : ['src'],
  dependencies : [threads, liburingpp_dep])
