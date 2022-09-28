#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>

#include "pattern.hpp"
#include "time.hpp"

struct Config {
    struct Server {
        uint32_t listenAddress = INADDR_ANY;
        uint16_t listenPort = 6969;

        bool accesLog = true;

        size_t listenBacklog = SOMAXCONN;
        uint32_t fullReadTimeoutMs = 1000;
        size_t maxUrlLength = 512;
        // maxRequestHeaderSize is actually the max size of request line + all headers
        // 1024 is enough for most requests, mostly less than MTU
        size_t maxRequestHeaderSize = 1024;
        size_t maxRequestBodySize = 1024;
    };

    struct Service : public Server {
        struct Host {
            struct PatternEntry {
                Pattern pattern;
                std::string replacement;
            };

            struct HeadersEntry {
                Pattern pattern;
                std::unordered_map<std::string, std::string> headers;
            };

            std::vector<PatternEntry> files;
            std::optional<std::string> metrics;
            std::vector<HeadersEntry> headers = {};
            std::vector<PatternEntry> redirects;
#ifdef TLS_SUPPORT_ENABLED
            std::optional<std::string> acmeChallenges;
#endif
        };

#ifdef TLS_SUPPORT_ENABLED
        struct Tls {
            // Do a variant here!
            std::optional<std::string> chain;
            std::optional<std::string> key;
            std::optional<std::string> acme;
        };

        std::optional<Tls> tls;
#endif

        std::unordered_map<std::string, Host> hosts;
    };

#ifdef TLS_SUPPORT_ENABLED
    struct Acme {
        // directoryUrl would be more descriptive, but it might be confusing with "directory" below
        std::string url = "letsencrypt";
        std::string domain; // the key of the object
        std::vector<std::string> altNames; // Subject Alternative Names
        std::string directory; // $XDG_DATA_HOME/htcpp/acme, XDG_DATA_HOME=$HOME/.local/share
        std::string accountPrivateKeyPath; // <directory>/accountkey.pem
        std::string certPrivateKeyPath; // <directory>/<domain>/privkey.pem
        std::string certPath; // <directory>/<domain>/fullchain.pem
        // certbot uses 2048 by default
        // also: https://danielpocock.com/rsa-key-sizes-2048-or-4096-bits/
        uint32_t rsaKeyLength = 2048;
        std::vector<TimePoint> renewCheckTimes = { { 3, 0 }, { 15, 0 } };
        // We jitter the time a bit (actually "wander") to avoid repeated
        // retries at inopportune times
        Duration renewCheckJitter = Duration::fromHours(3);
        // Lets Encrypt certificates are valid for 90 days by default, so we give ourselves
        // 60 days to attempt renewal (same as certbot)
        Duration renewBeforeExpiry = Duration::fromDays(30);
    };

    std::unordered_map<std::string, Acme> acme; // the key is the domain
#endif

    uint32_t ioQueueSize = 2048; // power of two, >= 1, <= 4096
    bool ioSubmissionQueuePolling = true;

    std::vector<Service> services;

    bool loadFromFile(const std::string& path);

    static Config& get();
};
