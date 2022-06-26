project('htcpp', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

threads_dep = dependency('threads')
openssl_dep = dependency('openssl', required : false)

clipp_dep = dependency('clipp', fallback : ['clipp', 'clipp_dep'])
cpprom_dep = dependency('cpprom', fallback : ['cpprom', 'cpprom_dep'], default_options : [ 'single_threaded=true' ])
joml_cpp_dep = dependency('joml-cpp', fallback : ['joml-cpp', 'joml_cpp_dep'])
liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])

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
  'src/metrics.cpp',
  'src/router.cpp',
  'src/server.cpp',
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

    clipp_dep,
    cpprom_dep,
    joml_cpp_dep,
    liburingpp_dep,
  ])
