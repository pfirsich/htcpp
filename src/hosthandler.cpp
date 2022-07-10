#include "hosthandler.hpp"

#include <filesystem>

#include <cpprom/cpprom.hpp>

#include "log.hpp"
#include "string.hpp"

namespace {
std::string_view toString(std::filesystem::file_type status)
{
    switch (status) {
    case std::filesystem::file_type::none:
        return "none";
    case std::filesystem::file_type::not_found:
        return "not found";
    case std::filesystem::file_type::regular:
        return "file";
    case std::filesystem::file_type::directory:
        return "directory";
    case std::filesystem::file_type::symlink:
        return "symlink";
    case std::filesystem::file_type::block:
        return "block device";
    case std::filesystem::file_type::character:
        return "character device";
    case std::filesystem::file_type::fifo:
        return "fifo";
    case std::filesystem::file_type::socket:
        return "socket";
    case std::filesystem::file_type::unknown:
        return "unknown";
    default:
        return "invalid";
    }
}
}

HostHandler::HostHandler(IoQueue& io, FileCache& fileCache,
    const std::unordered_map<std::string, Config::Service::Host>& config)
    : io_(io)
    , fileCache_(fileCache)
{
    for (const auto& [name, host] : config) {
        hosts_.emplace_back();
        hosts_.back().name = name;
        for (const auto& [urlPath, fsPath] : host.files) {
            const auto canonical = std::filesystem::canonical(fsPath); // Follow symlinks
            const auto type = std::filesystem::status(canonical).type();
            const auto severity = type == std::filesystem::file_type::regular
                    || type == std::filesystem::file_type::directory
                ? slog::Severity::Debug
                : slog::Severity::Warning;
            slog::log(
                severity, name, ": '", urlPath, "' -> '", canonical, "' (", toString(type), ")");
            hosts_.back().files.push_back(
                FilesEntry { urlPath, fsPath, type == std::filesystem::file_type::directory });
        }
        hosts_.back().metrics = host.metrics;
    }
}

HostHandler::HostHandler(const HostHandler& other)
    : io_(other.io_)
    , fileCache_(other.fileCache_)
    , hosts_(other.hosts_)
{
}

void HostHandler::operator()(const Request& request, std::shared_ptr<Responder> responder) const
{
    const Host* host = nullptr;
    const auto hostHeader = request.headers.get("Host");
    for (const auto& h : hosts_) {
        if (hostHeader && h.name == *hostHeader) {
            host = &h;
            break;
        } else if (h.name == "*") {
            host = &h;
        }
    }

    if (!host) {
        // RFC 2616:
        // All Internet-based HTTP/1.1 servers MUST respond with a 400 (Bad Request) status code
        // to any HTTP/1.1 request message which lacks a Host header field.
        // and:
        // If the host as determined by rule 1 or 2 is not a valid host on the server, the
        // response MUST be a 400 (Bad Request) error message.
        slog::debug("No matching host for '", hostHeader.value_or("(none)"), "'");
        responder->respond(Response(StatusCode::BadRequest, "Bad Request"));
        return;
    }

    if (host->metrics && request.url.path == *host->metrics) {
        metrics(request, std::move(responder));
    } else {
        files(request, std::move(responder), host->files);
    }
}

void HostHandler::metrics(const Request&, std::shared_ptr<Responder> responder) const
{
    io_.async<Response>(
        []() {
            return Response(
                cpprom::Registry::getDefault().serialize(), "text/plain; version=0.0.4");
        },
        [responder = std::move(responder)](std::error_code ec, Response&& response) mutable {
            assert(!ec);
            responder->respond(std::move(response));
        });
}

void HostHandler::files(const Request& request, std::shared_ptr<Responder> responder,
    const std::vector<FilesEntry>& files) const
{
    for (const auto& entry : files) {
        if (entry.isDirectory && startsWith(request.url.path, entry.urlPath)) {
            // url.path must start with a '/' (verified in Url::parse)
            const auto path = entry.fsPath + std::string(request.url.path);
            respondFile(path, std::move(responder));
            return;
        } else if (request.url.path == entry.urlPath) {
            respondFile(entry.fsPath, std::move(responder));
            return;
        }
    }
    responder->respond(Response(StatusCode::NotFound, "Not Found"));
}

void HostHandler::respondFile(const std::string& path, std::shared_ptr<Responder> responder) const
{
    const auto f = fileCache_.get(path);
    if (!f) {
        responder->respond(Response(StatusCode::NotFound, "Not Found"));
        return;
    }
    const auto extDelim = path.find_last_of('.');
    const auto ext = path.substr(std::min(extDelim + 1, path.size()));
    responder->respond(Response(*f, getMimeType(std::string(ext))));
}

std::string HostHandler::getMimeType(const std::string& fileExt)
{
    static std::unordered_map<std::string, std::string> mimeTypes {
        { "jpg", "image/jpeg" },
        { "html", "text/html" },
        { "png", "image/png" },
    };
    const auto it = mimeTypes.find(fileExt);
    if (it == mimeTypes.end()) {
        return "text/plain";
    }
    return it->second;
}
