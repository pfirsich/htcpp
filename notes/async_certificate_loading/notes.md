I want to reload the certificate chain and the private key when they change on disk (certbot renews both), but I wasn't sure if simply doing file IO asynchronously and then just using the OpenSSL certificate/key loading functions would be good enough.
There was a suspicion that reading the files will take a small percentage of the overall loading time, so that I might not end up decreasing the blocking time noticably at all.
As it turns out my suspicions were correct. I did these benchmarks on a DigitalOcean 5$ VM, which I am going to use for hosting my website anyways. It does use an SSD, which makes it even more likely that doing only file IO asynchronously will not do much.

A test certificate without a chain. Times are in microseconds.
```
root@tunnel:~# ./load_cert_sync
Duration: 2432
root@tunnel:~# ./load_cert_sync
Duration: 2835
root@tunnel:~# ./load_cert_sync
Duration: 2828
root@tunnel:~# ./load_cert_async
File read duration: 91
Load duration: 2438
root@tunnel:~# ./load_cert_async
File read duration: 102
Load duration: 2007
root@tunnel:~# ./load_cert_async
File read duration: 115
Load duration: 2642
```

A certificate that I actually use to host a website of mine right now
```
cert=/caddy-data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/REDACTED/REDACTED.crt
key=/caddy-data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/REDACTED/REDACTED.key

./load_cert_sync "$cert" "$key"
Duration: 5037
root@tunnel:~# ./load_cert_sync "$cert" "$key"
Duration: 5213
root@tunnel:~# ./load_cert_sync "$cert" "$key"
Duration: 5213

root@tunnel:~# ./load_cert_async "$cert" "$key"
File read duration: 119
Load duration: 5085
root@tunnel:~# ./load_cert_async "$cert" "$key"
File read duration: 117
Load duration: 4808
root@tunnel:~# ./load_cert_async "$cert" "$key"
File read duration: 134
Load duration: 5395
```

In both cases loading the file takes a very small amount of time while the whole process takes a few milliseconds. You could argue that it's fine to block for 5ms every 2 months, but this whole project is just an exercise, so I will instead offload the certificate reloading to a thread.

I need to implement this feature anyways, because I need it for process metrics as well.
