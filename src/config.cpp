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

    const auto joml = joml::parse(*source);
    if (!joml) {
        const auto err = joml.error();
        slog::error("Could not parse JOML config: ", err.string(), "\n",
            joml::getContextString(*source, err.position));
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
        } else if (key == "services") {
            if (!value.is<joml::Node::Dictionary>()) {
                slog::error("'services' must be a dictionary");
                return false;
            }
            for (const auto& [addr, jservice] : value.as<joml::Node::Dictionary>()) {
                auto& service = copy.services.emplace_back();

                auto ipPort = IpPort::parse(addr);
                if (!ipPort) {
                    slog::error("Invalid ip:addr string as service key: '", addr, "'");
                    return false;
                }
                if (ipPort->ip) {
                    service.listenAddress = *ipPort->ip;
                }
                service.listenPort = ipPort->port;

                if (!jservice.is<joml::Node::Dictionary>()) {
                    slog::error("service (element of 'services') must be a dictionary");
                    return false;
                }

                bool hostsFound = false;

                for (const auto& [skey, svalue] : jservice.as<joml::Node::Dictionary>()) {
                    if (skey == "access_log") {
                        if (!svalue.is<joml::Node::Bool>()) {
                            slog::error("'access_log' must be a boolean");
                            return false;
                        }
                        service.accesLog = svalue.as<joml::Node::Bool>();
                    } else if (skey == "tls") {
                        if (!svalue.is<joml::Node::Dictionary>()) {
                            slog::error("'tls' must be a dictionary");
                            return false;
                        }
                        service.tls.emplace();
                        bool chainFound = false;
                        bool keyFound = false;
                        for (const auto& [tkey, tvalue] : svalue.as<joml::Node::Dictionary>()) {
                            if (tkey == "chain") {
                                if (!tvalue.is<joml::Node::String>()) {
                                    slog::error("'chain' must be a string");
                                    return false;
                                }
                                service.tls->chain = tvalue.as<joml::Node::String>();
                                chainFound = true;
                            } else if (tkey == "key") {
                                if (!tvalue.is<joml::Node::String>()) {
                                    slog::error("'key' must be a string");
                                    return false;
                                }
                                service.tls->key = tvalue.as<joml::Node::String>();
                                keyFound = true;
                            } else {
                                slog::error("Invalid key '", tkey, "'");
                                return false;
                            }
                        }
                        if (!chainFound || !keyFound) {
                            slog::error("'chain' and 'key' are mandatory in 'tls'");
                            return false;
                        }
                    } else if (skey == "hosts") {
                        if (!svalue.is<joml::Node::Dictionary>()) {
                            slog::error("'hosts' must be a dictionary");
                            return false;
                        }
                        for (const auto& [hostName, jhost] : svalue.as<joml::Node::Dictionary>()) {
                            auto& host
                                = service.hosts.emplace(hostName, Service::Host {}).first->second;

                            if (!jhost.is<joml::Node::Dictionary>()) {
                                slog::error("host (element of 'hosts') must be a dictionary");
                                return false;
                            }

                            for (const auto& [hkey, hvalue] : jhost.as<joml::Node::Dictionary>()) {
                                if (hkey == "root") {
                                    if (!hvalue.is<joml::Node::String>()) {
                                        slog::error("'root' must be a string");
                                        return false;
                                    }
                                    host.root = hvalue.as<joml::Node::String>();
                                } else if (hkey == "metrics") {
                                    if (!hvalue.is<joml::Node::String>()) {
                                        slog::error("'metrics' must be a string");
                                        return false;
                                    }
                                    host.metrics = hvalue.as<joml::Node::String>();
                                } else {
                                    slog::error("Invalid key '", hkey, "'");
                                    return false;
                                }
                            }

                            hostsFound = true;
                        }
                    } else {
                        slog::error("Invalid key '", skey, "'");
                        return false;
                    }
                }

                if (!hostsFound) {
                    slog::error(
                        "'hosts' is mandatory in service '", addr, "' and must not be empty");
                    return false;
                }

                servicesFound = true;
            }

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
