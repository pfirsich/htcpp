#include "config.hpp"

#include "log.hpp"
#include "string.hpp"
#include "util.hpp"

#include <joml.hpp>

namespace {
template <typename T>
constexpr bool isPowerOfTwo(T v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

std::optional<std::string> substituteEnvVars(std::string_view source)
{
    std::string ret;
    size_t cursor = 0;
    while (cursor < source.size()) {
        const auto start = source.find("${", cursor);
        ret.append(source.substr(cursor, start - cursor));
        if (start == std::string_view::npos) {
            break;
        }

        const auto end = source.find("}", start);
        if (end == std::string_view::npos) {
            slog::error("Unmatched environment variable expansion");
            return std::nullopt;
        }

        const auto arg = source.substr(start + 2, end - start - 2);
        const auto colon = arg.find(':');
        const auto var = std::string(colon == std::string_view::npos ? arg : arg.substr(0, colon));
        const auto defaultValue = colon == std::string_view::npos
            ? std::optional<std::string_view> { std::nullopt }
            : std::optional<std::string_view> { arg.substr(colon + 1) };

        const auto envValue = ::getenv(var.c_str());
        if (envValue) {
            ret.append(envValue);
        } else if (defaultValue) {
            ret.append(*defaultValue);
        } else {
            slog::error("Environment variable '", var, "' is not defined.");
            return std::nullopt;
        }

        cursor = end + 1;
    }
    return ret;
}

std::optional<std::unordered_map<std::string, Config::Service::Host>> loadHosts(
    const joml::Node& node)
{
    if (!node.is<joml::Node::Dictionary>()) {
        slog::error("'hosts' must be a dictionary");
        return std::nullopt;
    }

    std::unordered_map<std::string, Config::Service::Host> hosts;
    for (const auto& [hostName, jhost] : node.as<joml::Node::Dictionary>()) {
        auto& host = hosts.emplace(hostName, Config::Service::Host {}).first->second;

        if (!jhost.is<joml::Node::Dictionary>()) {
            slog::error("host (element of 'hosts') must be a dictionary");
            return std::nullopt;
        }

        for (const auto& [hkey, hvalue] : jhost.as<joml::Node::Dictionary>()) {
            if (hkey == "files") {
                if (hvalue.is<joml::Node::String>()) {
                    host.files.emplace_back(
                        Config::Service::Host::FilesEntry { "/", hvalue.as<joml::Node::String>() });
                } else if (hvalue.is<joml::Node::Dictionary>()) {
                    for (const auto& [urlPath, fsPath] : hvalue.as<joml::Node::Dictionary>()) {
                        if (!fsPath.is<joml::Node::String>()) {
                            slog::error("'files' values must be a string");
                            return std::nullopt;
                        }
                        host.files.emplace_back(Config::Service::Host::FilesEntry {
                            urlPath, fsPath.as<joml::Node::String>() });
                    }
                } else {
                    slog::error("'files' must be a string or a dictionary");
                    return std::nullopt;
                }
            } else if (hkey == "metrics") {
                if (!hvalue.is<joml::Node::String>()) {
                    slog::error("'metrics' must be a string");
                    return std::nullopt;
                }
                host.metrics = hvalue.as<joml::Node::String>();
            } else if (hkey == "headers") {
                if (!hvalue.is<joml::Node::Dictionary>()) {
                    slog::error("headers (element of host) must be a dictionary");
                    return std::nullopt;
                }

                for (const auto& [patternStr, hdsvalue] : hvalue.as<joml::Node::Dictionary>()) {
                    if (!hdsvalue.is<joml::Node::Dictionary>()) {
                        slog::error("value of headers dictionary must be a dictionary too");
                        return std::nullopt;
                    }

                    auto pattern = Pattern::create(patternStr);
                    if (!pattern) {
                        return std::nullopt;
                    }

                    std::unordered_map<std::string, std::string> headers;
                    for (const auto& [headerName, headerValue] :
                        hdsvalue.as<joml::Node::Dictionary>()) {
                        if (!headerValue.is<joml::Node::String>()) {
                            slog::error(
                                "HTTP Header value for '", headerName, "' must be a string");
                            return std::nullopt;
                        }
                        headers.emplace(headerName, headerValue.as<joml::Node::String>());
                    }

                    host.headers.push_back(Config::Service::Host::HeadersEntry {
                        std::move(*pattern), std::move(headers) });
                }
            } else {
                slog::error("Invalid key '", hkey, "'");
                return std::nullopt;
            }
        }

        if (host.files.empty() && !host.metrics) {
            slog::error(
                "Must specify at least one of 'files' or 'metrics' for host ('", hostName, "')");
            return std::nullopt;
        }
    }
    return hosts;
}

std::optional<std::vector<Config::Service>> loadServices(const joml::Node& node)
{
    if (!node.is<joml::Node::Dictionary>()) {
        slog::error("'services' must be a dictionary");
        return std::nullopt;
    }
    std::vector<Config::Service> services;
    for (const auto& [addr, jservice] : node.as<joml::Node::Dictionary>()) {
        auto& service = services.emplace_back();

        auto ipPort = IpPort::parse(addr);
        if (!ipPort) {
            slog::error("Invalid ip:addr string as service key: '", addr, "'");
            return std::nullopt;
        }
        if (ipPort->ip) {
            service.listenAddress = *ipPort->ip;
        }
        service.listenPort = ipPort->port;

        if (!jservice.is<joml::Node::Dictionary>()) {
            slog::error("service (element of 'services') must be a dictionary");
            return std::nullopt;
        }

        for (const auto& [skey, svalue] : jservice.as<joml::Node::Dictionary>()) {
            if (skey == "access_log") {
                if (!svalue.is<joml::Node::Bool>()) {
                    slog::error("'access_log' must be a boolean");
                    return std::nullopt;
                }
                service.accesLog = svalue.as<joml::Node::Bool>();
            } else if (skey == "tls") {
                if (!svalue.is<joml::Node::Dictionary>()) {
                    slog::error("'tls' must be a dictionary");
                    return std::nullopt;
                }
                service.tls.emplace();
                bool chainFound = false;
                bool keyFound = false;
                for (const auto& [tkey, tvalue] : svalue.as<joml::Node::Dictionary>()) {
                    if (tkey == "chain") {
                        if (!tvalue.is<joml::Node::String>()) {
                            slog::error("'chain' must be a string");
                            return std::nullopt;
                        }
                        service.tls->chain = tvalue.as<joml::Node::String>();
                        chainFound = true;
                    } else if (tkey == "key") {
                        if (!tvalue.is<joml::Node::String>()) {
                            slog::error("'key' must be a string");
                            return std::nullopt;
                        }
                        service.tls->key = tvalue.as<joml::Node::String>();
                        keyFound = true;
                    } else {
                        slog::error("Invalid key '", tkey, "'");
                        return std::nullopt;
                    }
                }
                if (!chainFound || !keyFound) {
                    slog::error("'chain' and 'key' are mandatory in 'tls'");
                    return std::nullopt;
                }
            } else if (skey == "hosts") {
                const auto hosts = loadHosts(svalue);
                if (!hosts) {
                    return std::nullopt;
                }
                if (hosts->empty()) {
                    slog::error("'hosts' must not be empty");
                    return std::nullopt;
                }
                service.hosts = *hosts;
            } else {
                slog::error("Invalid key '", skey, "'");
                return std::nullopt;
            }
        }

        if (service.hosts.empty()) {
            slog::error("'hosts' is mandatory in service '", addr, "' and must not be empty");
            return std::nullopt;
        }
    }
    return services;
}
}

// Without all this generic schema stuff, this would be even larger and more complicated and more
// annoying to write.
bool Config::loadFromFile(const std::string& path)
{
    const auto source = readFile(path);
    if (!source) {
        // already logged
        return false;
    }

    const auto substSource = substituteEnvVars(*source);
    if (!substSource) {
        return false;
    }

    const auto joml = joml::parse(*substSource);
    if (!joml) {
        const auto err = joml.error();
        slog::error("Could not parse JOML config: ", err.string(), "\n",
            joml::getContextString(*substSource, err.position));
        return false;
    }

    auto copy = *this;

    bool servicesFound = false;

    for (const auto& [key, value] : *joml) {

        if (key == "io_queue_size") {
            if (!value.is<joml::Node::Integer>()) {
                slog::error("'io_queue_size' must be an integer");
                return false;
            }
            const auto qs = value.as<joml::Node::Integer>();
            if (qs < 1 || qs > 4096 || !isPowerOfTwo(qs)) {
                slog::error("'io_queue_size' must be power of two in [1, 4096]");
                return false;
            }
            copy.ioQueueSize = static_cast<size_t>(qs);
        } else if (key == "io_submission_queue_polling") {
            if (!value.is<joml::Node::Bool>()) {
                slog::error("'io_submission_queue_polling' must be a boolean");
                return false;
            }
            copy.ioSubmissionQueuePolling = value.as<joml::Node::Bool>();
        } else if (key == "services") {
            const auto services = loadServices(value);
            if (!services) {
                return false;
            }
            copy.services = *services;
            servicesFound = true;
        } else {
            slog::error("Invalid key '", key, '"');
            return false;
        }
    }

    if (!servicesFound) {
        slog::error("'services' is mandatory and must not be empty");
        return false;
    }

    *this = copy;

    return true;
}

Config& Config::get()
{
    static Config config;
    return config;
}
