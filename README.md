# httpserver

This is a HTTP/1.1 server built with [io_uring](https://en.wikipedia.org/wiki/Io_uring). It's single-threaded and all network IO and inotify usage is asynchronous.

Currently it has the following features:
* Handles basic HTTP/1.1 requests, parses them and responds
* Persistent Connections (it doesn't support pipelining though, because no one does)
* A cool URL [router](src/router.hpp) like all the popular web frameworks (see example in [main.cpp](src/main.cpp))
* FileCache/FileWatcher to serve files and automatically reload them (using inotify)
* TLS

It requires io_uring features that are available since kernel 5.5, so it will exit immediately on earlier kernels.

## Building
Install [meson](https://mesonbuild.com/).

Execute the following commands:
```shell
meson setup build/
meson compile -C build
```

If OpenSSL can be found during the build, TLS support is automatically enabled. The build will fail for OpenSSL versions earlier than `1.1.1`.

## Todo
* Find a name
* Nicer logging (with configurable log levels and access log)
* Reload certificates and recreate certificates if they are renewed
* certbot integration
* Docker image (optionally including certbot)
* URL percent decoding (didn't need it yet)
* Compression (didn't need it yet)
