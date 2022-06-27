#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>

struct Config {
    struct Server {
        uint32_t listenAddress = INADDR_ANY;
        uint16_t listenPort = 6969;

        bool accesLog = true;

        size_t listenBacklog = SOMAXCONN;
        size_t fullReadTimeoutMs = 1000;
        size_t maxUrlLength = 512;
        // maxRequestHeaderSize is actually the max size of request line + all headers
        // 1024 is enough for most requests, mostly less than MTU
        size_t maxRequestHeaderSize = 1024;
        size_t maxRequestBodySize = 1024;
    };

    struct Service : public Server {
        struct Host {
            std::optional<std::string> root;
            std::optional<std::string> metrics;
        };

#ifdef TLS_SUPPORT_ENABLED
        struct Tls {
            std::string chain;
            std::string key;
        };

        std::optional<Tls> tls;
#endif

        std::unordered_map<std::string, Host> hosts;
    };

    size_t ioQueueSize = 2048; // power of two, >= 1, <= 4096

    std::vector<Service> services;

    bool loadFromFile(const std::string& path);

    static Config& get();
};
