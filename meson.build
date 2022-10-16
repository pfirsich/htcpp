project('htcpp', 'cpp', default_options : ['warning_level=3', 'cpp_std=c++17'])

threads_dep = dependency('threads')
openssl_dep = dependency('openssl', required : false)

clipp_dep = dependency('clipp', fallback : ['clipp', 'clipp_dep'])
cpprom_dep = dependency('cpprom', fallback : ['cpprom', 'cpprom_dep'], default_options : [ 'single_threaded=true' ])
joml_cpp_dep = dependency('joml-cpp', fallback : ['joml-cpp', 'joml_cpp_dep'])
liburingpp_dep = dependency('liburingpp', fallback : ['liburingpp', 'liburingpp_dep'])
minijson_dep = dependency('minijson', fallback : ['minijson', 'minijson_dep'])

flags = []

lib_src = [
  'src/client.cpp',
  'src/events.cpp',
  'src/fd.cpp',
  'src/filecache.cpp',
  'src/filewatcher.cpp',
  'src/http.cpp',
  'src/ioqueue.cpp',
  'src/log.cpp',
  'src/metrics.cpp',
  'src/pattern.cpp',
  'src/router.cpp',
  'src/server.cpp',
  'src/string.cpp',
  'src/tcp.cpp',
  'src/time.cpp',
  'src/util.cpp',
]

if openssl_dep.found()
  lib_src += [
    'src/acme.cpp',
    'src/ssl.cpp',
  ]
  flags += '-DTLS_SUPPORT_ENABLED'
endif

htcpp_lib_deps = [
  threads_dep,
  openssl_dep,
  cpprom_dep,
  liburingpp_dep,
  minijson_dep,
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
    joml_cpp_dep,
  ],
)

executable('libexample', 'src/libexample.cpp',
  cpp_args : flags,
  include_directories : ['src'],
  dependencies : [
    htcpp_dep,
  ],
)

executable('clienttest', 'src/clienttest.cpp',
  cpp_args : flags,
  include_directories : ['src'],
  dependencies : [
    htcpp_dep,
  ],
)

unittests_src = [
  'unittests/main.cpp',
  'unittests/time.cpp',
]

executable('unittests', unittests_src,
  cpp_args : flags,
  include_directories : ['src'],
  dependencies : [
    htcpp_dep,
  ],
)
