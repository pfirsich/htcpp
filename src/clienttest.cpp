#include <cpprom/cpprom.hpp>

#include "client.hpp"
#include "events.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

#include <future>

class ThreadSafeRequester {
public:
    struct RequestResult {
        std::error_code ec;
        Response response;
    };

    ThreadSafeRequester(IoQueue& io)
        : io_(io)
        , eventListener_(io, [this](Event&& event) { eventHandler(std::move(event)); })
    {
    }

    std::future<RequestResult> request(
        Method method, std::string url, HeaderMap<> headers = {}, std::string body = {})
    {
        auto prom = std::make_shared<std::promise<RequestResult>>();
        auto fut = prom->get_future();
        eventListener_.emit(
            Event { method, std::move(url), std::move(headers), std::move(body), std::move(prom) });
        return fut;
    }

private:
    struct Event {
        Method method;
        std::string url;
        HeaderMap<> headers;
        std::string body;
        std::shared_ptr<std::promise<RequestResult>> promise;
    };

    void eventHandler(Event&& event)
    {
        ::request(io_, event.method, event.url, event.headers, event.body,
            [prom = std::move(event.promise)](std::error_code ec, Response&& resp) mutable {
                prom->set_value(RequestResult { ec, std::move(resp) });
            });
    }

    IoQueue& io_;
    EventListener<Event> eventListener_;
};

int main()
{
    slog::init(slog::Severity::Debug);

    IoQueue io;

    ThreadSafeRequester requester(io);

    std::thread t([&requester]() {
        const auto [ec, resp] = requester.request(Method::Get, "http://httpbin.org/get").get();

        if (ec) {
            slog::error("Error in request: ", ec.message());
            return;
        }

        slog::info("Status: ", static_cast<uint32_t>(resp.status));
        for (const auto& [name, value] : resp.headers.getEntries()) {
            slog::info("'", name, "': '", value, "'");
        }
        slog::info("Body:\n", resp.body);
    });

    io.run();

    return 0;
}
