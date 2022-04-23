#!/usr/bin/env sh
# Execute this script from the root of the repository

# Test like this:
# Server: openssl s_server -key key.pem -cert cert.pem -accept 5890 -www
# Client: curl --cacert cert.pem https://localhost:6969/

certtool --generate-privkey --outfile key.pem
certtool --generate-self-signed --load-privkey key.pem --template scripts/cert.cfg --outfile cert.pem

# The following openssl command will not generate a CA certificate, which it needs to be for curl
# openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out cert.pem -keyout key.pem
