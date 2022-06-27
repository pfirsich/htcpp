#include <filesystem>

#include <clipp.hpp>

#include "hosthandler.hpp"
#include "log.hpp"
#include "tcp.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

using namespace std::literals;

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
    std::optional<std::string> metrics;
    std::optional<std::string> arg = ".";

    void args()
    {
        flag(listen, "listen", 'l').valueNames("IPPORT").help("ip:port or port");
        flag(debug, "debug").help("Enable debug logging");
        // flag(followSymlinks, "follow", 'f').help("Follow symlinks");
#ifdef TLS_SUPPORT_ENABLED
        flag(tls, "tls").num(2).valueNames("CERT", "KEY");
#endif
        // flag(browse, "browse", 'b');
        flag(metrics, "metrics", 'm')
            .valueNames("ENDPOINT")
            .help("Endpoint for Prometheus-compatible metrics");
        positional(arg, "arg");
    }
};

int main(int argc, char** argv)
{
    auto parser = clipp::Parser(argv[0]);
    const Args args = parser.parse<Args>(argc, argv).value();
    slog::init(args.debug ? slog::Severity::Debug : slog::Severity::Info);

    auto& config = Config::get();
    if (std::filesystem::is_regular_file(args.arg.value())) {
        if (!config.loadFromFile(*args.arg)) {
            return 1;
        }
    } else if (std::filesystem::is_directory(args.arg.value())) {
        config.services.emplace_back();
        config.services.back().hosts.emplace("", Config::Service::Host { args.arg, args.metrics });
    } else {
        slog::error("Invalid argument. Must either be a config file or a directory to serve");
        return 1;
    }

    if (args.listen) {
        if (args.listen->ip) {
            config.services.back().listenAddress = *args.listen->ip;
        }
        config.services.back().listenPort = args.listen->port;
    }

#ifdef TLS_SUPPORT_ENABLED
    if (!args.tls.empty()) {
        config.services.back().tls.emplace(Config::Service::Tls { args.tls[0], args.tls[1] });
    }
#endif

    IoQueue io(config.ioQueueSize);

    // We share a file cache, because we don't need multiple and if we made it a member of
    // HostHandler, HostHandler would not be copyable anymore, which it needs to be to be part of
    // std::function (std::function copyable requirement is annoying again..)
    FileCache fileCache(io);

    std::vector<std::unique_ptr<Server<TcpConnectionFactory>>> tcpServers;

#ifdef TLS_SUPPORT_ENABLED
    std::vector<std::unique_ptr<Server<SslConnectionFactory>>> sslServers;
#endif

    for (const auto& service : config.services) {
        HostHandler handler(io, fileCache, service.hosts);

#ifdef TLS_SUPPORT_ENABLED
        if (service.tls) {
            auto factory = SslConnectionFactory(io, service.tls->chain, service.tls->key);
            if (!factory.contextManager->getCurrentContext()) {
                return 1;
            }

            auto server = std::make_unique<Server<SslConnectionFactory>>(
                io, std::move(factory), handler, service);
            server->start();
            sslServers.push_back(std::move(server));
        } else {
            auto server = std::make_unique<Server<TcpConnectionFactory>>(
                io, TcpConnectionFactory {}, handler, service);
            server->start();
            tcpServers.push_back(std::move(server));
        }
#else
        auto server = std::make_unique<Server<TcpConnectionFactory>>(
            io, TcpConnectionFactory {}, handler, service);
        server->start();
        tcpServers.push_back(std::move(server));
#endif
    }
    io.run();
    return 0;
}
