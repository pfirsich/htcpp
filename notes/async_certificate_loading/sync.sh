#!/bin/bash
g++ load_cert_sync.cpp -lssl -o load_cert_sync && ./load_cert_sync "$1" "$2"
