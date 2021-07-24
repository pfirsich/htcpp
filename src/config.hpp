#pragma once

struct Config {
    uint16_t listenPort = 6969;
    uint32_t listenAddress = INADDR_ANY;
    size_t listenBacklog = 1024;
    size_t ioQueueSize = 1024; // power of two, >= 1, <= 4096
    size_t readAmount = 128;
    size_t singleReadTimeoutMs = 512; // todo
    size_t fullReadTimeoutMs = 1024; // todo
    size_t maxUrlLength = 2048;
    size_t maxRequestSize = 8192; // todo
    size_t defaultRequestSize = 512; // Initial buffer size

    static Config& get()
    {
        static Config config;
        return config;
    }
};
