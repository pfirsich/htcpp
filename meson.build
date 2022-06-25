project('htcpp', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])
clipp_dep = dependency('clipp', fallback : ['clipp', 'clipp_dep'])
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
  'src/log.cpp',
  'src/main.cpp',
  'src/router.cpp',
  'src/server.cpp',
  'src/stats.cpp',
  'src/string.cpp',
  'src/util.cpp',
]

if openssl_dep.found()
  src += 'src/ssl.cpp'
  flags += '-DTLS_SUPPORT_ENABLED'
endif

executable('htcpp', src, include_directories : ['src'],
  cpp_args : flags,
  dependencies : [
    threads_dep,
    openssl_dep,
    liburingpp_dep,
    clipp_dep,
  ])
