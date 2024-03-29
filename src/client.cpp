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

ThreadRequester::ThreadRequester(IoQueue& io)
    : io_(io)
    , eventListener_(io, [this](Event&& event) { eventHandler(std::move(event)); })
{
}

std::future<ThreadRequester::RequestResult> ThreadRequester::request(
    Method method, std::string url, HeaderMap<> headers, std::string body)
{
    auto prom = std::make_shared<std::promise<RequestResult>>();
    auto fut = prom->get_future();
    eventListener_.emit(
        Event { std::move(prom), method, std::move(url), std::move(headers), std::move(body) });
    return fut;
}

void ThreadRequester::eventHandler(ThreadRequester::Event&& event)
{
    ::request(io_, event.method, event.url, event.headers, event.body,
        [prom = std::move(event.promise)](std::error_code ec, Response&& resp) mutable {
            if (ec) {
                prom->set_value(Result<Response>(error(ec)));
            } else {
                prom->set_value(Result<Response>(std::move(resp)));
            }
        });
}
