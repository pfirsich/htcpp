#include <cpprom/cpprom.hpp>

#include "client.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

int main()
{
    slog::init(slog::Severity::Debug);

    IoQueue io;

    request(io, Method::Get, "https://httpbin.org/get", {}, "",
        [](std::error_code ec, Response&& resp) {
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
