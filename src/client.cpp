#include "client.hpp"

void request(IoQueue& io, Method method, const std::string_view urlStr, const HeaderMap<>& headers,
    const std::string& requestBody, std::function<void(std::error_code, Response&&)> cb)
{
    const auto url = Url::parse(urlStr);
    if (!url) {
        slog::error("Could not parse URL for request");
        cb(std::make_error_code(std::errc::invalid_argument), Response());
        return;
    }
    if (url->scheme == "http") {
        auto session = ClientSession<TcpConnectionFactory>::create(io, url->host, url->port);
        session->request(method, url->targetRaw, headers, requestBody, std::move(cb));
#ifdef TLS_SUPPORT_ENABLED
    } else if (url->scheme == "https") {
        auto session = ClientSession<SslClientConnectionFactory>::create(io, url->host, url->port);
        session->request(method, url->targetRaw, headers, requestBody, std::move(cb));
#endif
    } else {
        cb(std::make_error_code(std::errc::invalid_argument), Response());
        slog::error("Invalid scheme in request url");
        return;
    }
}

