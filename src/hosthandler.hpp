#pragma once

#include "config.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "server.hpp"

class HostHandler {
public:
    HostHandler(IoQueue& io, FileCache& fileCache,
        const std::unordered_map<std::string, Config::Service::Host>& config);

    HostHandler(const HostHandler& other);

    void operator()(const Request& request, std::shared_ptr<Responder> responder) const;

private:
    struct FilesEntry {
        std::string urlPath;
        std::string fsPath;
        bool isDirectory = false;
    };

    struct Host {
        std::string name;
        std::vector<FilesEntry> files;
        std::optional<std::string> metrics;
    };

    static std::string getMimeType(const std::string& fileExt);

    void metrics(const Request&, std::shared_ptr<Responder> responder) const;

    void files(const Request& request, std::shared_ptr<Responder> responder,
        const std::vector<FilesEntry>& root) const;

    void respondFile(const std::string& path, std::shared_ptr<Responder> responder) const;

    IoQueue& io_;
    FileCache& fileCache_;
    std::vector<Host> hosts_;
};
