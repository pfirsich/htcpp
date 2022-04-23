#include "config.hpp"
#include "fd.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "router.hpp"
#include "server.hpp"
#include "ssl.hpp"

using namespace std::literals;

int main()
{
    std::cout << "Starting HTTP server.." << std::endl;
    const auto& config = Config::get();
    std::cout << "listenPort: " << config.listenPort << std::endl;
    std::cout << "listenBacklog: " << config.listenBacklog << std::endl;
    std::cout << "ioQueueSize: " << config.ioQueueSize << std::endl;
    std::cout << "readAmount: " << config.readAmount << std::endl;
    std::cout << "singleReadTimeoutMs: " << config.singleReadTimeoutMs << std::endl;
    std::cout << "fullReadTimeoutMs: " << config.fullReadTimeoutMs << std::endl;
    std::cout << "maxUrlLength: " << config.maxUrlLength << std::endl;
    std::cout << "maxRequestSize: " << config.maxRequestSize << std::endl;
    std::cout << "defaultRequestSize: " << config.defaultRequestSize << std::endl;

    SslContextManager::instance().init("cert.pem", "key.pem");

    IoQueue io(config.ioQueueSize);

    FileCache fileCache(io);

    Router router;

    router.route("/", Method::Get,
        [](const Request&, const Router::RouteParams&) -> Response { return "Hello!"s; });

    router.route("/foo", Method::Get,
        [](const Request&, const Router::RouteParams&) -> Response { return "This is foo"s; });

    router.route("/headers", [](const Request& req, const Router::RouteParams&) -> Response {
        std::string s;
        s.reserve(1024);
        for (const auto& [name, value] : req.headers.getEntries()) {
            s.append("'" + std::string(name) + "' = '" + std::string(value) + "'\n");
        }
        return s;
    });

    router.route("/users/:uid", [](const Request&, const Router::RouteParams& params) -> Response {
        return "User #'" + std::string(params.at("uid")) + "'";
    });

    router.route(
        "/users/:uid/name", [](const Request&, const Router::RouteParams& params) -> Response {
            return "User name for #'" + std::string(params.at("uid")) + "'";
        });

    router.route("/users/:uid/friends/:fid",
        [](const Request&, const Router::RouteParams& params) -> Response {
            return "Friend #'" + std::string(params.at("fid")) + "' for user '"
                + std::string(params.at("uid")) + "'";
        });

    router.route("/users/:uid/files/:path*",
        [](const Request&, const Router::RouteParams& params) -> Response {
            return "File '" + std::string(params.at("path")) + "' for user '"
                + std::string(params.at("uid")) + "'";
        });

    router.route("/file/:path*",
        [&fileCache](const Request&, const Router::RouteParams& params) -> Response {
            const auto f = fileCache.get(std::string(params.at("path")));
            if (!f) {
                return Response(StatusCode::NotFound, "Not Found");
            }
            return Response(*f, "text/plain");
        });

    Server server(io, router);
    server.start();
}
