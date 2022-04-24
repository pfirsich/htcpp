#pragma once

#include <netinet/in.h>

struct Config {
    uint16_t listenPort = 6969;
    uint32_t listenAddress = INADDR_ANY;
    size_t listenBacklog = SOMAXCONN;
    size_t ioQueueSize = 2048; // power of two, >= 1, <= 4096
    size_t readAmount = 1024; // Enough for most requests, mostly less than MTU
    size_t singleReadTimeoutMs = 512; // todo
    size_t fullReadTimeoutMs = 1024; // todo
    size_t maxUrlLength = 512;
    size_t maxRequestSize = 8192;
    size_t defaultRequestSize = 512; // Initial buffer size

    static Config& get();
};
