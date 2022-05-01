#pragma once

#include <netinet/in.h>

struct Config {
    bool useTls = false;
    uint16_t listenPort = 6969;
    uint32_t listenAddress = INADDR_ANY;
    bool accesLog = true;
    bool debugLogging = true;

    size_t listenBacklog = SOMAXCONN;
    size_t ioQueueSize = 2048; // power of two, >= 1, <= 4096
    size_t singleReadTimeoutMs = 512; // todo
    size_t fullReadTimeoutMs = 1024; // todo
    size_t maxUrlLength = 512;
    // maxRequestHeaderSize is actually the max size of request line + all headers
    // 1024 is enough for most requests, mostly less than MTU
    size_t maxRequestHeaderSize = 1024;
    size_t maxRequestBodySize = 1024;

    static Config& get();
};
