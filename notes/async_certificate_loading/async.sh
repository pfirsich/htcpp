#!/bin/bash
g++ load_cert_async.cpp -lssl -lcrypto -o load_cert_async && ./load_cert_async "$1" "$2"
