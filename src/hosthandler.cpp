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

void HostHandler::Host::addHeaders(std::string_view requestPath, Response& response) const
{
    for (const auto& rule : headers) {
        if (rule.pattern.match(requestPath).match) {
            for (const auto& [name, value] : rule.headers) {
                if (value.empty()) {
                    response.headers.remove(name);
                } else {
                    response.headers.set(name, value);
                }
            }
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
        hosts_.back().headers = host.headers;
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
        metrics(*host, request, std::move(responder));
    } else {
        files(*host, request, std::move(responder));
    }
}

void HostHandler::metrics(const HostHandler::Host& host, const Request& request,
    std::shared_ptr<Responder> responder) const
{
    if (request.method != Method::Get) {
        responder->respond(Response(StatusCode::MethodNotAllowed));
        return;
    }

    io_.async<Response>(
        []() {
            return Response(
                cpprom::Registry::getDefault().serialize(), "text/plain; version=0.0.4");
        },
        [&host, requestPath = request.url.path, responder = std::move(responder)](
            std::error_code ec, Response&& response) mutable {
            assert(!ec);
            host.addHeaders(requestPath, response);
            responder->respond(std::move(response));
        });
}

void HostHandler::files(const HostHandler::Host& host, const Request& request,
    std::shared_ptr<Responder> responder) const
{
    for (const auto& entry : host.files) {
        if (entry.isDirectory && startsWith(request.url.path, entry.urlPath)) {
            // request.url.path must start with a '/' (verified in Url::parse)
            const auto path = entry.fsPath + std::string(request.url.path);
            respondFile(host, path, request, std::move(responder));
            return;
        } else if (request.url.path == entry.urlPath) {
            respondFile(host, entry.fsPath, request, std::move(responder));
            return;
        }
    }
    responder->respond(Response(StatusCode::NotFound, "Not Found"));
}

void HostHandler::respondFile(const HostHandler::Host& host, const std::string& path,
    const Request& request, std::shared_ptr<Responder> responder) const
{
    if (request.method != Method::Get && request.method != Method::Head) {
        responder->respond(Response(StatusCode::MethodNotAllowed));
        return;
    }

    const auto f = fileCache_.get(path);
    if (!f) {
        responder->respond(Response(StatusCode::NotFound, "Not Found"));
        return;
    }

    const auto ifNoneMatch = request.headers.get("If-None-Match");
    if (ifNoneMatch && ifNoneMatch->find(f->eTag) != std::string_view::npos) {
        // It seems to me I don't have to include ETag and Last-Modified here, but I am not sure.
        responder->respond(Response(StatusCode::NotModified));
        return;
    }

    const auto ifModifiedSince = request.headers.get("If-Modified-Since");
    if (ifModifiedSince && f->lastModified == *ifModifiedSince) {
        responder->respond(Response(StatusCode::NotModified));
        return;
    }

    const auto extDelim = path.find_last_of('.');
    const auto ext = path.substr(std::min(extDelim + 1, path.size()));
    auto resp = Response(StatusCode::Ok);
    resp.headers.add("ETag", f->eTag);
    resp.headers.add("Last-Modified", f->lastModified);
    resp.headers.add("Content-Type", getMimeType(std::string(ext)));
    if (request.method == Method::Get) {
        resp.body = f->contents.value();
    } else {
        assert(request.method == Method::Head);
        resp.headers.add("Content-Length", std::to_string(f->contents->size()));
    }
    host.addHeaders(request.url.path, resp);
    responder->respond(std::move(resp));
}

std::string HostHandler::getMimeType(const std::string& fileExt)
{
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
    static std::unordered_map<std::string, std::string> mimeTypes {
        { "aac", "audio/aac" },
        { "abw", "application/x-abiword" },
        { "arc", "application/x-freearc" },
        { "avif", "image/avif" },
        { "avi", "video/x-msvideo" },
        { "azw", "application/vnd.amazon.ebook" },
        { "bin", "application/octet-stream" },
        { "bmp", "image/bmp" },
        { "bz", "application/x-bzip" },
        { "bz2", "application/x-bzip2" },
        { "cda", "application/x-cdf" },
        { "csh", "application/x-csh" },
        { "css", "text/css" },
        { "csv", "text/csv" },
        { "doc", "application/msword" },
        { "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
        { "eot", "application/vnd.ms-fontobject" },
        { "epub", "application/epub+zip" },
        { "gz", "application/gzip" },
        { "gif", "image/gif" },
        { "htm", "text/html" },
        { "html", "text/html" },
        { "ico", "image/vnd.microsoft.icon" },
        { "ics", "text/calendar" },
        { "jar", "application/java-archive" },
        { "jpeg", "image/jpeg" },
        { "jpg", "image/jpeg" },
        { "js", "text/javascript" },
        { "json", "application/json" },
        { "jsonld", "application/ld+json" },
        { "mid", "audio/midi" },
        { "midi", "audio/midi" },
        { "mjs", "text/javascript" },
        { "mp3", "audio/mpeg" },
        { "mp4", "video/mp4" },
        { "mpeg", "video/mpeg" },
        { "mpkg", "application/vnd.apple.installer+xml" },
        { "odp", "application/vnd.oasis.opendocument.presentation" },
        { "ods", "application/vnd.oasis.opendocument.spreadsheet" },
        { "odt", "application/vnd.oasis.opendocument.text" },
        { "oga", "audio/ogg" },
        { "ogv", "video/ogg" },
        { "ogx", "application/ogg" },
        { "opus", "audio/opus" },
        { "otf", "font/otf" },
        { "png", "image/png" },
        { "pdf", "application/pdf" },
        { "php", "application/x-httpd-php" },
        { "ppt", "application/vnd.ms-powerpoint" },
        { "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
        { "rar", "application/vnd.rar" },
        { "rtf", "application/rtf" },
        { "sh", "application/x-sh" },
        { "svg", "image/svg+xml" },
        { "swf", "application/x-shockwave-flash" },
        { "tar", "application/x-tar" },
        { "tif", "image/tiff" },
        { "tiff", "image/tiff" },
        { "ts", "video/mp2t" },
        { "ttf", "font/ttf" },
        { "txt", "text/plain" },
        { "vsd", "application/vnd.visio" },
        { "wav", "audio/wav" },
        { "weba", "audio/webm" },
        { "webm", "video/webm" },
        { "webp", "image/webp" },
        { "woff", "font/woff" },
        { "woff2", "font/woff2" },
        { "xhtml", "application/xhtml+xml" },
        { "xls", "application/vnd.ms-excel" },
        { "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
        { "xml", "application/xml" },
        { "xul", "application/vnd.mozilla.xul+xml" },
        { "zip", "application/zip" },
        { "3gp", "video/3gpp" }, // could be audio/3gpp as well
        { "3g2", "video/3gpp2" }, // could be audio/3gpp2 as well
        { "7z", "application/x-7z-compressed" },
    };
    const auto it = mimeTypes.find(fileExt);
    if (it == mimeTypes.end()) {
        return "application/octet-stream";
    }
    return it->second;
}
