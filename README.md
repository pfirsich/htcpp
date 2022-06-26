# htcpp

A HTTP/1.1 server using [io_uring](https://en.wikipedia.org/wiki/Io_uring) built with C++17. It's single-threaded and all network IO and inotify usage is asynchronous.

Currently it has the following features:
* Handles basic HTTP/1.1 requests, parses them and responds
* Persistent Connections (it doesn't support pipelining though, because no one does)
* A cool URL [router](src/router.hpp) like all the popular web frameworks (see example in [main.cpp](src/main.cpp))
* FileCache/FileWatcher to serve files and automatically reload them (using inotify)
* TLS
* Built-in [Prometheus](https://prometheus.io/)-compatible metrics using [cpprom](https://github.com/pfirsich/cpprom/) (at `/metrics` - configurable later)
* The only dependency that is not another project of mine is OpenSSL

It requires io_uring features that are available since kernel 5.5, so it will exit immediately on earlier kernels.

## Building
Install [meson](https://mesonbuild.com/).

Execute the following commands:
```shell
meson setup build/
meson compile -C build
```

If OpenSSL can be found during the build, TLS support is automatically enabled. The build will fail for OpenSSL versions earlier than `1.1.1`.

## To Do (Must)
* **Fix: Handle pending bytes to write for TLS correctly. Currently I complete an SSL operation even if there are pending bytes. I need a more elaborate state machine**.
* Config files and possibility to host multiple websites
* Reload certificate/private key when they change on disk
* Make it possible to have request handlers do other async IO (pass a continuation instead of using return value?)
* Add a mechanism that dispatches work to a thread pool and notifies the IO queue via an eventfd, so I can do e.g. certificate loading and process metrics asynchronously
* Add request read timeout (to be less susceptible to trickle attacks). I have not done this yet, because it's tricky with SSL right now. Note: Be aware of connection reuse, i.e. idle connections should time out, overly long requests should time out, single reads should also time out.
* Make it work with certbot: If I implement automatic reloading of certificates and implement multiple websites, so I can host .well-known/acme-challenge on port 80, then I think the rest is just configuration.
* Make file reading asynchronous (there are a bunch of problem with this though)

## To Do (Should)
* Improve behaviour in case of DDos (esp. in conjunction with Cloudflare DDoS protection) - from here: https://fasterthanli.me/articles/i-won-free-load-testing (great post!)
    - Respond with 429/503 or start refusing connections if overloaded (likely both, but at different levels?)
    - Add concurrency limit (max number of concurrent connections)
    - Read timeout (see above)
* URL percent decoding (didn't need it yet)

## To Do (Could)
* Large file transfer (with `sendfile` or `slice`)
    - Support HEAD requests for file server
    - [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since]
    - Partial Content ([Range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range)
    - [ETag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)/[If-Match](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match) support
* IPv6
* Directory Listings
* HTTP Client
* (after HTTP Client) Reverse proxy mode
* (After Config) Header-Editing Rules (Add, Replace, Remove Headers)
* Customizable access log: Have the option to include some request headers, like Referer or User-Agent

## Won't Do (for now?)
* Compression: Afaik you are supposed to disable it for images and other already compressed assets (obviously), but since I only plan to serve small HTML pages with this, there is not much use.
* Support for kTLS: It's probably a good performance improvement, but quite involved and I don't need it.
* Dispatch HTTP sessions to a thread pool (to increase TLS performance): I will likely only deploy this on very small single vCPU VMs
* chroot "jail": According to the man page you should not use these for security, so if you want filesystem isolation, use Docker
* Dropping privileges: Not hard to do, but the same applies. If you want to deploy it securely, use Docker.
