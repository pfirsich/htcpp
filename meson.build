project('httpserver', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])
threads_dep = dependency('threads')
openssl_dep = dependency('openssl', required : false)

flags = []

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

if openssl_dep.found()
  src += 'src/ssl.cpp'
  flags += '-DOPENSSL_FOUND'
endif

executable('httpserver', src, include_directories : ['src'],
  dependencies : [threads_dep, liburingpp_dep, openssl_dep, zlib_dep])
