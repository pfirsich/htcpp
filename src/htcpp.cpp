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

    static std::optional<IpPort> parse(std::string_view str) { return IpPort::parse(str); }
};

struct Args : clipp::ArgsBase {
    std::optional<IpPort> listen;
    bool debug = false;
    bool checkConfig = false;
    // bool followSymlinks;
    // bool browse;
    std::optional<std::string> metrics;
    std::optional<std::string> arg = ".";

    void args()
    {
        flag(listen, "listen", 'l').valueNames("IPPORT").help("ip:port or port");
        flag(debug, "debug").help("Enable debug logging");
        flag(checkConfig, "check-config").help("Check the configuration and exit");
        // flag(followSymlinks, "follow", 'f').help("Follow symlinks");
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
    parser.version("1.1.0");
    const Args args = parser.parse<Args>(argc, argv).value();
    slog::init(args.debug ? slog::Severity::Debug : slog::Severity::Info);

    auto& config = Config::get();
    if (std::filesystem::is_regular_file(args.arg.value())) {
        if (!config.loadFromFile(*args.arg)) {
            return 1;
        }
    } else if (std::filesystem::is_directory(args.arg.value())) {
        auto& service = config.services.emplace_back();
        Config::Service::Host host;
        host.files.push_back({ Pattern::create("/*").value(), pathJoin(*args.arg, "$1") });
        host.metrics = args.metrics;
        host.headers.push_back(
            { Pattern::create("*").value(), { { "Cache-Control", "no-store" } } });
        service.hosts.emplace("*", std::move(host));
    } else {
        slog::error("Invalid argument. Must either be a config file or a directory to serve");
        return 1;
    }

    if (args.checkConfig) {
        return 0;
    }

    if (args.listen) {
        if (args.listen->ip) {
            config.services.back().listenAddress = *args.listen->ip;
        }
        config.services.back().listenPort = args.listen->port;
    }

    IoQueue io(config.ioQueueSize, config.ioSubmissionQueuePolling);

    // We share a file cache, because we don't need to separate them per host (in fact we might risk
    // duplication otherwise)
    FileCache fileCache(io);

    std::vector<std::unique_ptr<Server<TcpConnectionFactory>>> tcpServers;

#ifdef TLS_SUPPORT_ENABLED
    std::vector<std::unique_ptr<Server<SslServerConnectionFactory>>> sslServers;
    std::vector<std::unique_ptr<Server<AcmeSslConnectionFactory>>> acmeSslServers;

    for (const auto& [name, config] : config.acme) {
        registerAcmeClient(name, io, config);
    }
#endif

    for (const auto& service : config.services) {
        HostHandler handler(io, fileCache, service.hosts);

#ifdef TLS_SUPPORT_ENABLED
        if (service.tls) {
            if (service.tls->acme) {
                auto factory = AcmeSslConnectionFactory { getAcmeClient(*service.tls->acme) };
                auto server = std::make_unique<Server<AcmeSslConnectionFactory>>(
                    io, std::move(factory), std::move(handler), service);
                server->start();
                acmeSslServers.push_back(std::move(server));
            } else {
                assert(service.tls->chain && service.tls->key);
                auto factory
                    = SslServerConnectionFactory(io, *service.tls->chain, *service.tls->key);
                if (!factory.contextManager->getCurrentContext()) {
                    return 1;
                }

                auto server = std::make_unique<Server<SslServerConnectionFactory>>(
                    io, std::move(factory), std::move(handler), service);
                server->start();
                sslServers.push_back(std::move(server));
            }
        } else {
            auto server = std::make_unique<Server<TcpConnectionFactory>>(
                io, TcpConnectionFactory {}, std::move(handler), service);
            server->start();
            tcpServers.push_back(std::move(server));
        }
#else
        auto server = std::make_unique<Server<TcpConnectionFactory>>(
            io, TcpConnectionFactory {}, std::move(handler), service);
        server->start();
        tcpServers.push_back(std::move(server));
#endif

        for (const auto& [name, host] : service.hosts) {
            std::vector<std::string> hosting;
            if (host.files.size()) {
                hosting.push_back("files");
            }
            if (host.metrics) {
                hosting.push_back("metrics");
            }
            if (host.acmeChallenges) {
                hosting.push_back("acme-challenges");
            }
            if (host.redirects.size()) {
                hosting.push_back("redirects");
            }
            slog::info("Host '", name, "': ", join(hosting));
        }
    }
    io.run();
    return 0;
}
