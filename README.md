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
meson subprojects update
meson compile -C build
```

If OpenSSL can be found during the build, TLS support is automatically enabled. The build will fail for OpenSSL versions earlier than `1.1.1`.

## To Do
* **Fix: Handle pending bytes to write for TLS correctly. Currently I complete an SSL operation even if there are pending bytes. I need a more elaborate state machine**.
* Find a name
* Add request read timeout (to be less susceptible to trickle attacks). I have not done this yet, because it's tricky with SSL right now. Note: Be aware of connection reuse, i.e. idle connections should time out, overly long requests should time out, single reads should also time out.
* Improve behaviour in case of DDos (esp. in conjunction with Cloudflare DDoS protection) - from here: https://fasterthanli.me/articles/i-won-free-load-testing (great post!)
    - Respond with 429/503 or start refusing connections if overloaded (likely both, but at different levels?)
    - Add concurrency limit (max number of concurrent connections)
    - Read timeout (see above)
* certbot integration (includes reloading certificates if they are renewed). I am not sure what exactly that entails right now, but I know that I want it to work.
* Docker image
    - Optionally include certbot
* Support HEAD requests for file server
* [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since] for file server
* IPv6
* URL percent decoding (didn't need it yet)
* Large file transfer (with `sendfile` or `slice`)
* Partial Content ([Range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range) for file server
    - Also add [ETag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)[If-Match](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match) support
* Directory Listings
* Customizable access log: Have the option to include some request headers, like Referer or User-Agent

## Won't Do (for now?)
* Compression: Afaik you are supposed to disable it for images and other already compressed assets (obviously), but since I only plan to serve small HTML pages with this, there is not much use.
* Support for kTLS: It's probably a good performance improvement, but quite involved and I don't need it.
* Dispatch HTTP sessions to a thread pool (to increase TLS performance): I will likely only deploy this on very small single vCPU VMs
* chroot "jail": According to the man page you should not use these for security, so if you want filesystem isolation, use Docker
* Dropping privileges: Not hard to do, but the same applies. If you want to deploy it securely, use Docker.
