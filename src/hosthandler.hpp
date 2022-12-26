#pragma once

#include "config.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "pattern.hpp"
#include "server.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "acme.hpp"
#endif

class HostHandler {
public:
    HostHandler(IoQueue& io, FileCache& fileCache,
        const std::unordered_map<std::string, Config::Service::Host>& config);

    HostHandler(const HostHandler& other);

    void operator()(const Request& request, std::unique_ptr<Responder> responder) const;

private:
    struct FilesEntry {
        Pattern urlPattern;
        std::string fsPath;
        bool needsGroupReplacement;
    };

    struct Host {
        std::string name;
        std::vector<FilesEntry> files;
        std::optional<std::string> metrics;
        std::vector<Config::Service::Host::HeadersEntry> headers;
#ifdef TLS_SUPPORT_ENABLED
        // weak_ptr would probably be better, but I don't want to pay for it.
        // The connection factory owns the AcmeClient.
        std::vector<AcmeClient*> acmeChallenges;
#endif
        std::vector<Config::Service::Host::PatternEntry> redirects;

        void addHeaders(std::string_view requestPath, Response& response) const;
    };

    static std::string getMimeType(const std::string& fileExt);

    bool isMetricsRoute(const Host& host, const Request& request) const;
    void respondMetrics(
        const Host& host, const Request&, std::unique_ptr<Responder> responder) const;

#ifdef TLS_SUPPORT_ENABLED
    std::optional<std::string> getAcmeChallenge(const Host& host, const Request& request) const;
    void respondAcmeChallenge(const std::string& challengeContent, const Request& request,
        std::unique_ptr<Responder> responder) const;
#endif

    std::optional<std::string> getRedirect(const Host& host, const Request& request) const;
    void respondRedirect(const std::string& target, const Request& request,
        std::unique_ptr<Responder> responder) const;

    std::optional<std::string> getFile(const Host& host, const Request& request) const;
    void respondFile(const Host& host, const std::string& path, const Request& request,
        std::unique_ptr<Responder> responder) const;

    IoQueue& io_;
    FileCache& fileCache_;
    std::vector<Host> hosts_;
};
