#include <cpprom/cpprom.hpp>

#include "client.hpp"
#include "events.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

int main()
{
    slog::init(slog::Severity::Debug);

    IoQueue io;

    ThreadRequester requester(io);

    std::thread t([&requester]() {
        const auto res = requester.request(Method::Get, "http://httpbin.org/get").get();

        if (!res) {
            slog::error("Error in request: ", res.error().message());
            return;
        }

        slog::info("Status: ", static_cast<uint32_t>(res->status));
        for (const auto& [name, value] : res->headers.getEntries()) {
            slog::info("'", name, "': '", value, "'");
        }
        slog::info("Body:\n", res->body);
    });

    io.run();

    return 0;
}
