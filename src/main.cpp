#include "config.hpp"
#include "fd.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "router.hpp"
#include "server.hpp"
#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

using namespace std::literals;

static std::string getMimeType(std::string fileExt)
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

int main()
{
    std::cout << "Starting HTTP server.." << std::endl;
    const auto& config = Config::get();
    std::cout << "useTls: " << config.useTls << std::endl;
    std::cout << "listenPort: " << config.listenPort << std::endl;
    std::cout << "listenBacklog: " << config.listenBacklog << std::endl;
    std::cout << "ioQueueSize: " << config.ioQueueSize << std::endl;
    std::cout << "readAmount: " << config.readAmount << std::endl;
    std::cout << "singleReadTimeoutMs: " << config.singleReadTimeoutMs << std::endl;
    std::cout << "fullReadTimeoutMs: " << config.fullReadTimeoutMs << std::endl;
    std::cout << "maxUrlLength: " << config.maxUrlLength << std::endl;
    std::cout << "maxRequestSize: " << config.maxRequestSize << std::endl;
    std::cout << "defaultRequestSize: " << config.defaultRequestSize << std::endl;

    if (!SslContextManager::instance().init("cert.pem", "key.pem")) {
        return 1;
    }

    IoQueue io(config.ioQueueSize);

    FileCache fileCache(io);

    Router router;

    router.route("/", Method::Get,
        [](const Request&, const Router::RouteParams&) -> Response { return "Hello!"s; });

    router.route("/number/:num", Method::Get,
        [](const Request&, const Router::RouteParams& params) -> Response {
            return "Number: "s + std::string(params.at("num"));
        });

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
            const auto path = params.at("path");
            const auto f = fileCache.get(std::string(path));
            if (!f) {
                return Response(StatusCode::NotFound, "Not Found");
            }
            const auto extDelim = path.find_last_of('.');
            const auto ext = path.substr(std::min(extDelim + 1, path.size()));
            return Response(*f, getMimeType(std::string(ext)));
        });

    if (config.useTls) {
#ifdef TLS_SUPPORT_ENABLED
        Server<SslConnection> server(io, router);
        server.start();
#else
        std::cerr << "Not compiled with TLS support" << std::endl;
        return 1;
#endif
    } else {
        Server<TcpConnection> server(io, router);
        server.start();
    }

    return 0;
}
