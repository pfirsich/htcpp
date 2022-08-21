#pragma once

#include "config.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "pattern.hpp"
#include "server.hpp"

class HostHandler {
public:
    HostHandler(IoQueue& io, FileCache& fileCache,
        const std::unordered_map<std::string, Config::Service::Host>& config);

    HostHandler(const HostHandler& other);

    void operator()(const Request& request, std::shared_ptr<Responder> responder) const;

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

        void addHeaders(std::string_view requestPath, Response& response) const;
    };

    static std::string getMimeType(const std::string& fileExt);

    void metrics(const Host& host, const Request&, std::shared_ptr<Responder> responder) const;

    void files(
        const Host& host, const Request& request, std::shared_ptr<Responder> responder) const;

    void respondFile(const Host& host, const std::string& path, const Request& request,
        std::shared_ptr<Responder> responder) const;

    IoQueue& io_;
    FileCache& fileCache_;
    std::vector<Host> hosts_;
};
