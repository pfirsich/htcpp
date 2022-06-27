#pragma once

#include "config.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "server.hpp"

class HostHandler {
public:
    HostHandler(IoQueue& io, FileCache& fileCache,
        std::unordered_map<std::string, Config::Service::Host> config);

    HostHandler(const HostHandler& other);

    void operator()(const Request& request, std::shared_ptr<Responder> responder) const;

private:
    void metrics(const Request&, std::shared_ptr<Responder> responder) const;

    void files(const Request& request, std::shared_ptr<Responder> responder,
        const std::string& root) const;

    static std::string getMimeType(const std::string& fileExt);

    IoQueue& io_;
    FileCache& fileCache_;
    std::unordered_map<std::string, Config::Service::Host> config_;
    Config::Service::Host* defaultHost_ = nullptr;
};
