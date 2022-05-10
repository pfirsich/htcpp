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
* Fix: Handle pending bytes to write for TLS correctly. Currently I complete an SSL operation even if there are pending bytes. I need a more elaborate state machine.
* Find a name
* Add request read timeout (to be less susceptible to trickle attacks). I have not done this yet, because it's tricky with SSL right now.
* Improve behaviour in case of DDos (esp. in conjunction with Cloudflare DDoS protection) - from here: https://fasterthanli.me/articles/i-won-free-load-testing (great post!)
    - Respond with 429/503 or start refusing connections if overloaded (likely both, but at different levels?)
    - Add concurrency limit (max number of concurrent connections)
    - Read timeout (see above)
* certbot integration (includes reloading certificates if they are renewed)
* Docker image
    - Optionally include certbot
    - Optionally only allow Cloudflare IPs via iptables (https://developers.cloudflare.com/fundamentals/get-started/task-guides/origin-health/free/)
* Support for kTLS (currently unnecessary performance improvement)
* Dispatch HTTP sessions to a thread pool (to increase TLS performance). I will likely only deploy this on very small single vCPU VMs, so I don't need this yet.
* IPv6
* URL percent decoding (didn't need it yet)
* Compression (didn't need it yet)
* Large file transfer (with `sendfile` or `slice`)
