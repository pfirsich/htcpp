project('htcpp', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

threads_dep = dependency('threads')
openssl_dep = dependency('openssl', required : false)

clipp_dep = dependency('clipp', fallback : ['clipp', 'clipp_dep'])
cpprom_dep = dependency('cpprom', fallback : ['cpprom', 'cpprom_dep'], default_options : [ 'single_threaded=true' ])
liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])

flags = []

lib_src = [
  'src/fd.cpp',
  'src/filecache.cpp',
  'src/filewatcher.cpp',
  'src/http.cpp',
  'src/ioqueue.cpp',
  'src/log.cpp',
  'src/metrics.cpp',
  'src/router.cpp',
  'src/server.cpp',
  'src/string.cpp',
  'src/tcp.cpp',
  'src/util.cpp',
]

if openssl_dep.found()
  lib_src += 'src/ssl.cpp'
  flags += '-DTLS_SUPPORT_ENABLED'
endif

htcpp_lib_deps = [
  threads_dep,
  openssl_dep,
  cpprom_dep,
  liburingpp_dep,
]

# This is not really clean, but it's a start
htcpp_inc = include_directories('src')
htcpp_lib = static_library('htcpp', lib_src,
  cpp_args : flags,
  include_directories : htcpp_inc,
  dependencies : htcpp_lib_deps,
)
htcpp_dep = declare_dependency(
  compile_args : flags,
  include_directories : htcpp_inc,
  link_with : htcpp_lib,
  # Not quite sure why I need this: https://github.com/mesonbuild/meson/issues/10543
  dependencies : htcpp_lib_deps,
)

bin_src = [
  'src/config.cpp',
  'src/hosthandler.cpp',
  'src/htcpp.cpp',
]

executable('htcpp', bin_src,
  cpp_args : flags,
  include_directories : ['src'],
  dependencies : [
    htcpp_dep,
    clipp_dep,
  ],
)
