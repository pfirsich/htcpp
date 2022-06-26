#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <clipp.hpp>
#include <cpprom/cpprom.hpp>

#include "config.hpp"
#include "fd.hpp"
#include "filecache.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "log.hpp"
#include "router.hpp"
#include "server.hpp"
#include "tcp.hpp"

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

struct IpPort {
    std::optional<uint32_t> ip;
    uint16_t port;

    static std::optional<IpPort> parse(std::string_view str)
    {
        auto ipStr = std::string_view();
        auto portStr = std::string_view();

        const auto colon = str.find(':');
        if (colon == std::string::npos) {
            portStr = str;
        } else {
            ipStr = str.substr(0, colon);
            portStr = str.substr(colon + 1);
        }

        std::optional<uint32_t> ip;
        if (!ipStr.empty()) {
            ip = parseIpAddress(std::string(ipStr));
            if (!ip) {
                return std::nullopt;
            }
        }

        const auto port = parseInt<uint16_t>(portStr);
        if (!port) {
            return std::nullopt;
        }

        return IpPort { ip, *port };
    }
};

template <>
struct clipp::Value<IpPort> {
    static constexpr std::string_view typeName = "[address:]port";

    static std::optional<IpPort> parse(std::string_view str)
    {
        return IpPort::parse(str);
    }
};

struct Args : clipp::ArgsBase {
    std::optional<IpPort> listen;
    bool debug;
    // bool followSymlinks;
#ifdef TLS_SUPPORT_ENABLED
    std::vector<std::string> tls;
#endif
    // bool browse;
    // std::string source = ".";

    void args()
    {
        flag(listen, "listen", 'l').valueNames("IPPORT").help("ip:port or port");
        flag(debug, "debug").help("Enable debug logging");
        // flag(followSymlinks, "follow", 'f').help("Follow symlinks");
#ifdef TLS_SUPPORT_ENABLED
        flag(tls, "tls").num(2).valueNames("CERT", "KEY");
#endif
        // flag(browse, "browse", 'b');
        // positional(source, "source").optional();
    }
};

int main(int argc, char** argv)
{
    auto parser = clipp::Parser(argv[0]);
    const Args args = parser.parse<Args>(argc, argv).value();

    auto& config = Config::get();

    if (args.listen) {
        if (args.listen->ip) {
            config.listenAddress = *args.listen->ip;
        }
        config.listenPort = args.listen->port;
    }

#ifdef TLS_SUPPORT_ENABLED
    if (!args.tls.empty()) {
        config.certPath = args.tls[0];
        config.keyPath = args.tls[1];
    }
#endif

    config.debugLogging = config.debugLogging || args.debug;

    slog::init(config.debugLogging ? slog::Severity::Debug : slog::Severity::Info);
#ifdef TLS_SUPPORT_ENABLED
    slog::info("Certificate Path: ", config.certPath.value_or("<none>"));
    slog::info("Private Key Path: ", config.keyPath.value_or("<none>"));
#endif
    slog::info("Listen Port: ", config.listenPort);
    slog::info("Listen Address: ", ::inet_ntoa(::in_addr { config.listenAddress }));
    slog::info("Access Log: ", config.accesLog);
    slog::info("Debug Logging: ", config.debugLogging);

    slog::debug("Listen Backlog: ", config.listenBacklog);
    slog::debug("IO Queue Size: ", config.ioQueueSize);
    slog::debug("Full Read Timeout (ms): ", config.fullReadTimeoutMs);
    slog::debug("Max URL Length: ", config.maxUrlLength);
    slog::debug("Max Request Header Size: ", config.maxRequestHeaderSize);
    slog::debug("Max Request Body Size: ", config.maxRequestBodySize);

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

    router.route("/metrics", [](const Request&, const Router::RouteParams&) -> Response {
        return Response(cpprom::Registry::getDefault().serialize(), "text/plain; version=0.0.4");
    });

#ifdef TLS_SUPPORT_ENABLED
    if (config.certPath && config.keyPath) {
        if (!SslContextManager::instance().init(*config.certPath, *config.keyPath)) {
            return 1;
        }

        Server<SslConnection> server(io, router);
        server.start();
        return 0;
    }
#endif

    Server<TcpConnection> server(io, router);
    server.start();
    return 0;
}
