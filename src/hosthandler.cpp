#include "hosthandler.hpp"

#include <cpprom/cpprom.hpp>

#include "log.hpp"

HostHandler::HostHandler(IoQueue& io, FileCache& fileCache,
    std::unordered_map<std::string, Config::Service::Host> config)
    : io_(io)
    , fileCache_(fileCache)
    , config_(config)
{
    const auto it = config_.find("*");
    if (it != config_.end()) {
        defaultHost_ = &it->second;
    }
}

HostHandler::HostHandler(const HostHandler& other)
    : HostHandler(other.io_, other.fileCache_, other.config_)
{
}

void HostHandler::operator()(const Request& request, std::shared_ptr<Responder> responder) const
{
    const Config::Service::Host* host = defaultHost_;
    const auto hostHeader = request.headers.get("Host");
    if (hostHeader) {
        const auto it = config_.find(std::string(*hostHeader));
        if (it != config_.end()) {
            host = &it->second;
        }
    }

    if (!host) {
        // RFC 2616:
        // All Internet-based HTTP/1.1 servers MUST respond with a 400 (Bad Request) status code
        // to any HTTP/1.1 request message which lacks a Host header field.
        // and:
        // If the host as determined by rule 1 or 2 is not a valid host on the server, the
        // response MUST be a 400 (Bad Request) error message.
        responder->respond(Response(StatusCode::BadRequest, "Bad Request"));
        return;
    }

    if (host->metrics && request.url.path == *host->metrics) {
        metrics(request, std::move(responder));
    } else if (host->root) {
        files(request, std::move(responder), *host->root);
    } else {
        responder->respond(Response(StatusCode::NotFound, "Not Found"));
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

void HostHandler::files(
    const Request& request, std::shared_ptr<Responder> responder, const std::string& root) const
{
    // url.path must start with a '/' (verified in Url::parse)
    const auto path = root + std::string(request.url.path);
    const auto f = fileCache_.get(std::string(path));
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
    };
    const auto it = mimeTypes.find(fileExt);
    if (it == mimeTypes.end()) {
        return "text/plain";
    }
    return it->second;
}
