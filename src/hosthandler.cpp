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
        for (const auto& [urlPattern, fsPath] : host.files) {
            std::error_code ec;
            if (urlPattern.isLiteral()) {
                const auto canonical = std::filesystem::canonical(fsPath, ec); // Follow symlinks
                if (ec) {
                    slog::error("Could not canonicalize '", fsPath, "': ", ec.message());
                    std::exit(1);
                }

                const auto status = std::filesystem::status(canonical, ec);
                if (ec) {
                    slog::error("Could not stat '", canonical.string(), "': ", ec.message());
                    std::exit(1);
                }

                if (std::filesystem::is_directory(status)) {
                    auto pattern = Pattern::create(pathJoin(urlPattern.raw(), "*")).value();
                    auto path = pathJoin(fsPath, "$1");
                    hosts_.back().files.push_back(FilesEntry { pattern, path, true });
                    slog::debug(name, ": '", pattern.raw(), "' -> '", path, "' (directory)");
                } else {
                    hosts_.back().files.push_back(FilesEntry { urlPattern, fsPath, false });
                    const auto severity = status.type() == std::filesystem::file_type::regular
                        ? slog::Severity::Debug
                        : slog::Severity::Warning;
                    slog::log(severity, name, ": '", urlPattern.raw(), "' -> '", canonical, "' (",
                        toString(status.type()), ")");
                }
            } else {
                hosts_.back().files.push_back(
                    FilesEntry { urlPattern, fsPath, Pattern::hasGroupReferences(fsPath) });
                slog::debug(name, ": '", urlPattern.raw(), "' -> '", fsPath, "'");
            }
        }
        hosts_.back().metrics = host.metrics;
        hosts_.back().headers = host.headers;
        hosts_.back().redirects = host.redirects;
#ifdef TLS_SUPPORT_ENABLED
        if (host.acmeChallenges) {
            hosts_.back().acmeChallenges.push_back(getAcmeClient(*host.acmeChallenges));
        }
#endif
    }
}

HostHandler::HostHandler(const HostHandler& other)
    : io_(other.io_)
    , fileCache_(other.fileCache_)
    , hosts_(other.hosts_)
{
}

void HostHandler::operator()(const Request& request, std::unique_ptr<Responder> responder) const
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

    if (isMetricsRoute(*host, request)) {
        respondMetrics(*host, request, std::move(responder));
#ifdef TLS_SUPPORT_ENABLED
    } else if (const auto challenge = getAcmeChallenge(*host, request)) {
        respondAcmeChallenge(*challenge, request, std::move(responder));
#endif
    } else if (const auto redirect = getRedirect(*host, request)) {
        respondRedirect(*redirect, request, std::move(responder));
    } else if (const auto file = getFile(*host, request)) {
        respondFile(*host, *file, request, std::move(responder));
    } else {
        responder->respond(Response(StatusCode::NotFound, "Not Found"));
    }
}

bool HostHandler::isMetricsRoute(const HostHandler::Host& host, const Request& request) const
{
    return host.metrics && request.url.path == *host.metrics;
}

void HostHandler::respondMetrics(const HostHandler::Host& host, const Request& request,
    std::unique_ptr<Responder> responder) const
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

#ifdef TLS_SUPPORT_ENABLED
std::optional<std::string> HostHandler::getAcmeChallenge(
    const Host& host, const Request& request) const
{
    for (const auto& client : host.acmeChallenges) {
        const auto challenges = client->getChallenges();
        for (const auto& challenge : *challenges) {
            if (challenge.path == request.url.path) {
                return challenge.content;
            }
        }
    }
    return std::nullopt;
}

void HostHandler::respondAcmeChallenge(const std::string& challengeContent, const Request& request,
    std::unique_ptr<Responder> responder) const
{
    if (request.method != Method::Get) {
        responder->respond(Response(StatusCode::MethodNotAllowed));
    }
    // The example in RFC8555 also uses application/octet-stream:
    // https://www.rfc-editor.org/rfc/rfc8555#section-8.3
    responder->respond(Response(StatusCode::Ok, challengeContent, "application/octet-stream"));
}
#endif

constexpr std::string_view redirectBody = R"(<html>
    <head>
        <meta charset="utf-8">
        <title>301 Moved</title>
    </head>
    <body>
        <h1>301 Moved</h1>
        The document has moved <a href="LOCATION">here</a>.
    </body>
</html>)";

std::optional<std::string> HostHandler::getRedirect(
    const HostHandler::Host& host, const Request& request) const
{
    for (const auto& entry : host.redirects) {
        const auto res = entry.pattern.match(request.url.path);
        if (res.match) {
            return Pattern::replaceGroupReferences(entry.replacement, res.groups);
        }
    }
    return std::nullopt;
}

void HostHandler::respondRedirect(
    const std::string& target, const Request& request, std::unique_ptr<Responder> responder) const
{
    static constexpr auto locationStart = redirectBody.find("LOCATION");
    static const auto redirectBodyPrefix = std::string(redirectBody.substr(0, locationStart));
    static const auto redirectBodySuffix
        = std::string(redirectBody.substr(locationStart + std::string_view("LOCATION").size()));

    auto resp = Response(StatusCode::MovedPermanently);
    resp.headers.add("Location", target);
    if (request.method == Method::Get) {
        // RFC2616 says the response body SHOULD contain a note with a hyperlink to the new
        // URL, but if I don't add it, both curl and Firefox stall on the response forever
        // and never actually follow the redirect.
        resp.body = redirectBodyPrefix + target + redirectBodySuffix;
        resp.headers.add("Content-Type", "text/html");
    } else if (request.method != Method::Head) {
        responder->respond(Response(StatusCode::MethodNotAllowed));
        return;
    }
    responder->respond(std::move(resp));
}

std::optional<std::string> HostHandler::getFile(
    const HostHandler::Host& host, const Request& request) const
{
    for (const auto& entry : host.files) {
        const auto res = entry.urlPattern.match(request.url.path);
        if (res.match) {
            if (entry.needsGroupReplacement) {
                return Pattern::replaceGroupReferences(entry.fsPath, res.groups);
            } else {
                return entry.fsPath;
            }
        }
    }
    return std::nullopt;
}

void HostHandler::respondFile(const HostHandler::Host& host, const std::string& path,
    const Request& request, std::unique_ptr<Responder> responder) const
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
