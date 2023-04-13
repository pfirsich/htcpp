#include "config.hpp"

#include <cassert>
#include <filesystem>

#include <pwd.h>
#include <unistd.h>

#include <joml.hpp>

#include "log.hpp"
#include "string.hpp"
#include "util.hpp"

namespace fs = std::filesystem;

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

template <typename T>
bool loadSingle(const joml::Node& value, std::string_view name, std::string_view typeName, T& dest)
{
    if (!value) {
        return true;
    }
    if (!value.is<T>()) {
        slog::error("'", name, "' must be a ", typeName);
        return false;
    }
    dest = value.as<T>();
    return true;
}

template <typename T>
bool loadInteger(const joml::Node& value, std::string_view name, T& dest)
{
    int64_t i = 0;
    if (!loadSingle(value, name, "integer", i)) {
        return false;
    }

    constexpr int64_t min = std::numeric_limits<T>::min();
    constexpr int64_t max = std::numeric_limits<T>::max();
    if (i < min || i > max) {
        slog::error("'", name, "' must be in [", min, ", ", max, "]");
        return false;
    }

    dest = static_cast<T>(i);
    return true;
}

bool load(const joml::Node& value, std::string_view name, bool& dest)
{
    return loadSingle(value, name, "boolean", dest);
}

bool load(const joml::Node& value, std::string_view name, int64_t& dest)
{
    return loadSingle(value, name, "integer", dest);
}

bool load(const joml::Node& value, std::string_view name, std::string& dest)
{
    return loadSingle(value, name, "string", dest);
}

template <typename T>
bool loadParse(const joml::Node& value, std::string_view name, std::string_view typeName, T& dest)
{
    std::string str;
    if (!value) {
        return true;
    }
    if (!load(value, name, str)) {
        return false;
    }
    const auto parsed = T::parse(str);
    if (!parsed) {
        slog::error("'", name, "' must be a valid ", typeName);
        return false;
    }
    dest = *parsed;
    return true;
}

bool load(const joml::Node& value, std::string_view name, TimePoint& dest)
{
    return loadParse(value, name, "time point (HH:MM[:SS])", dest);
}

bool load(const joml::Node& value, std::string_view name, Duration& dest)
{
    return loadParse(value, name, "duration (XXd, XXh, XXm or XXs)", dest);
}

template <typename T>
bool load(const joml::Node& value, std::string_view name, std::optional<T>& dest)
{
    if (!value) {
        return true;
    }
    return load(value, name, dest.emplace());
}

template <typename T>
bool load(const joml::Node& value, std::string_view name, std::vector<T>& dest)
{
    if (!value) {
        return true;
    }
    if (!value.isArray()) {
        slog::error("'", name, "' must be an array");
        return false;
    }
    const auto& arr = value.asArray();
    dest.clear();
    for (size_t i = 0; i < arr.size(); ++i) {
        if (!load(arr[i], std::string(name) + "[" + std::to_string(i) + "]", dest.emplace_back())) {
            return false;
        }
    }
    return true;
}

#define CHECK_OR_NULLOPT(cond)                                                                     \
    if (!(cond)) {                                                                                 \
        return std::nullopt;                                                                       \
    }

std::optional<std::string> getEnv(const std::string& name)
{
    const auto val = ::getenv(name.c_str());
    if (!val) {
        return std::nullopt;
    }
    return std::string(val);
}

fs::path getHomeDirectory()
{
    const auto envHome = getEnv("HOME");
    if (envHome) {
        return *envHome;
    }
    const auto uid = ::geteuid();
    const auto pw = getpwuid(uid);
    if (!pw) {
        slog::error("Could not get user directory");
        std::exit(1);
    }
    return fs::path(pw->pw_dir);
}

fs::path getXdgDataDirectory()
{
    const auto xdgData = getEnv("XDG_DATA_HOME");
    if (xdgData) {
        return *xdgData;
    }
    return getHomeDirectory() / ".local/share";
}

fs::path getDataDirectory()
{
    return getXdgDataDirectory() / "htcpp";
}

std::optional<Config::Acme> loadAcme(const std::string& domain, const joml::Node& node)
{
    if (!node.isDictionary()) {
        slog::error("'acme' must be a dictionary");
        return std::nullopt;
    }

    Config::Acme acme;
    acme.domain = domain;
    bool directoryFound = false;
    bool accountPrivateKeyPathFound = false;
    bool certPrivateKeyPathFound = false;
    bool certPathFound = false;
    for (const auto& [akey, avalue] : node.asDictionary()) {
        if (akey == "url") {
            CHECK_OR_NULLOPT(load(avalue, "url", acme.url));
        } else if (akey == "alt_names") {
            CHECK_OR_NULLOPT(load(avalue, "alt_names", acme.altNames));
        } else if (akey == "directory") {
            CHECK_OR_NULLOPT(load(avalue, "alt_names", acme.directory));
            directoryFound = true;
        } else if (akey == "account_private_key_path") {
            CHECK_OR_NULLOPT(load(avalue, "alt_names", acme.altNames));
            accountPrivateKeyPathFound = true;
        } else if (akey == "cert_private_key_path") {
            CHECK_OR_NULLOPT(load(avalue, "cert_private_key_path", acme.certPrivateKeyPath));
            certPrivateKeyPathFound = true;
        } else if (akey == "cert_path") {
            CHECK_OR_NULLOPT(load(avalue, "cert_path", acme.certPath));
            certPathFound = true;
        } else if (akey == "rsa_key_length") {
            int64_t length = 0;
            CHECK_OR_NULLOPT(load(avalue, "rsa_key_length", length));
            if (length != 1024 && length != 2048 && length != 3072 && length != 4096) {
                // First three are valid FIPS options, 4096 is something people use as well.
                slog::error("RSA key length must be in {1024, 2048, 3072, 4096}");
                return std::nullopt;
            }
            acme.rsaKeyLength = static_cast<uint32_t>(length);
        } else if (akey == "renew_check_times") {
            CHECK_OR_NULLOPT(load(avalue, "renew_check_times", acme.renewCheckTimes));
        } else if (akey == "renew_check_jitter") {
            CHECK_OR_NULLOPT(load(avalue, "renew_check_jitter", acme.renewCheckJitter));
        } else if (akey == "renew_before_expiry") {
            CHECK_OR_NULLOPT(load(avalue, "renew_before_expiry", acme.renewBeforeExpiry));
        } else {
            slog::error("Invalid key '", akey, "'");
            return std::nullopt;
        }
    }

    if (acme.url == "letsencrypt") {
        acme.url = "https://acme-v02.api.letsencrypt.org/directory";
    } else if (acme.url == "letsencrypt-staging") {
        acme.url = "https://acme-staging-v02.api.letsencrypt.org/directory";
    }

    // Don't set the defaults before the loop, but only if we have to, because getHomeDirectory
    // might fail and we don't want it to fail, when we don't even use the result.
    if (!directoryFound) {
        acme.directory = getDataDirectory() / "acme";
    }
    if (!accountPrivateKeyPathFound) {
        acme.accountPrivateKeyPath = fs::path(acme.directory) / "accountkey.pem";
    }
    if (!certPrivateKeyPathFound) {
        acme.certPrivateKeyPath = fs::path(acme.directory) / domain / "privkey.pem";
    }
    if (!certPathFound) {
        acme.certPath = fs::path(acme.directory) / domain / "fullchain.pem";
    }

    return acme;
}

template <typename Entry>
bool loadPatternRules(const joml::Node& node, std::string_view name, std::vector<Entry>& entries)
{
    if (!node.isDictionary()) {
        slog::error("'", name, "' must be a dictionary");
        return false;
    }

    for (const auto& [key, value] : node.asDictionary()) {
        auto pattern = Pattern::create(key);
        if (!pattern) {
            slog::error("Invalid pattern '", key, "'");
            return false;
        }

        if (!value.isString()) {
            slog::error("Value for pattern '", key, "' must be a string");
            return false;
        }

        const auto path = value.asString();
        if (!pattern->isValidReplacementString(path)) {
            slog::error("'", path, "' is not a valid replacement string");
            return false;
        }

        entries.push_back(Entry { *pattern, path });
    }
    return true;
}

std::optional<std::unordered_map<std::string, Config::Service::Host>> loadHosts(
    const joml::Node& node)
{
    if (!node.isDictionary()) {
        slog::error("'hosts' must be a dictionary");
        return std::nullopt;
    }

    std::unordered_map<std::string, Config::Service::Host> hosts;
    for (const auto& [hostName, jhost] : node.asDictionary()) {
        auto& host = hosts.emplace(hostName, Config::Service::Host {}).first->second;

        if (!jhost.isDictionary()) {
            slog::error("host (element of 'hosts') must be a dictionary");
            return std::nullopt;
        }

        for (const auto& [hkey, hvalue] : jhost.asDictionary()) {
            if (hkey == "files") {
                if (hvalue.isString()) {
                    host.files.emplace_back(Config::Service::Host::PatternEntry {
                        Pattern::create("/").value(), hvalue.asString() });
                } else if (hvalue.isDictionary()) {
                    if (!loadPatternRules(hvalue, "files", host.files)) {
                        return std::nullopt;
                    }
                } else {
                    slog::error("'files' must be a string or a dictionary");
                    return std::nullopt;
                }
            } else if (hkey == "metrics") {
                if (!hvalue.isString()) {
                    slog::error("'metrics' must be a string");
                    return std::nullopt;
                }
                host.metrics = hvalue.asString();
            } else if (hkey == "headers") {
                if (!hvalue.isDictionary()) {
                    slog::error("headers (element of host) must be a dictionary");
                    return std::nullopt;
                }

                for (const auto& [patternStr, hdsvalue] : hvalue.asDictionary()) {
                    if (!hdsvalue.isDictionary()) {
                        slog::error("value of headers dictionary must be a dictionary too");
                        return std::nullopt;
                    }

                    auto pattern = Pattern::create(patternStr);
                    if (!pattern) {
                        return std::nullopt;
                    }

                    std::unordered_map<std::string, std::string> headers;
                    for (const auto& [headerName, headerValue] : hdsvalue.asDictionary()) {
                        if (!headerValue.isString()) {
                            slog::error(
                                "HTTP Header value for '", headerName, "' must be a string");
                            return std::nullopt;
                        }
                        headers.emplace(headerName, headerValue.asString());
                    }

                    host.headers.push_back(Config::Service::Host::HeadersEntry {
                        std::move(*pattern), std::move(headers) });
                }
            } else if (hkey == "redirects") {
                if (!loadPatternRules(hvalue, "redirects", host.redirects)) {
                    return std::nullopt;
                }
#ifdef TLS_SUPPORT_ENABLED
            } else if (hkey == "acme_challenges") {
                CHECK_OR_NULLOPT(load(hvalue, "acme_challenges", host.acmeChallenges));
#endif
            } else {
                slog::error("Invalid key '", hkey, "'");
                return std::nullopt;
            }
        }

        if (host.files.empty() && !host.metrics && host.redirects.empty() && !host.acmeChallenges) {
            slog::error("Must specify at least one of 'acme-challenges', 'files', 'metrics' or "
                        "'redirects' for host ('",
                hostName, "')");
            return std::nullopt;
        }
    }
    return hosts;
}

std::optional<std::vector<Config::Service>> loadServices(const joml::Node& node)
{
    if (!node.isDictionary()) {
        slog::error("'services' must be a dictionary");
        return std::nullopt;
    }
    std::vector<Config::Service> services;
    for (const auto& [addr, jservice] : node.asDictionary()) {
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

        if (!jservice.isDictionary()) {
            slog::error("service (element of 'services') must be a dictionary");
            return std::nullopt;
        }

        for (const auto& [skey, svalue] : jservice.asDictionary()) {
            if (skey == "access_log") {
                if (!svalue.isBool()) {
                    slog::error("'access_log' must be a boolean");
                    return std::nullopt;
                }
                service.accesLog = svalue.asBool();
            } else if (skey == "limit_connections") {
                if (!svalue.isInteger()) {
                    slog::error("'limit_connections' must be an integer");
                    return std::nullopt;
                }
                service.limitConnections = svalue.asInteger();
            } else if (skey == "limit_requests_by_ip") {
                if (!svalue.isDictionary()) {
                    slog::error("'limit_requests_by_ip' must be a dictionary");
                    return std::nullopt;
                }
                service.limitRequestsByIp.emplace();
                for (const auto& [lkey, lvalue] : svalue.asDictionary()) {
                    if (lkey == "steady_rate") {
                        CHECK_OR_NULLOPT(loadInteger(
                            lvalue, "steady_rate", service.limitRequestsByIp->steadyRate));
                    } else if (lkey == "burst_size") {
                        CHECK_OR_NULLOPT(loadInteger(
                            lvalue, "burst_size", service.limitRequestsByIp->burstSize));
                    } else if (lkey == "max_num_entries") {
                        CHECK_OR_NULLOPT(loadInteger(
                            lvalue, "max_num_entries", service.limitRequestsByIp->maxNumEntries));
                    } else {
                        slog::error("Invalid key '", lkey, "'");
                        return std::nullopt;
                    }
                }
            } else if (skey == "tls") {
                if (!svalue.isDictionary()) {
                    slog::error("'tls' must be a dictionary");
                    return std::nullopt;
                }
                service.tls.emplace();
                for (const auto& [tkey, tvalue] : svalue.asDictionary()) {
                    if (tkey == "chain") {
                        CHECK_OR_NULLOPT(load(tvalue, "chain", service.tls->chain));
                    } else if (tkey == "key") {
                        CHECK_OR_NULLOPT(load(tvalue, "key", service.tls->key));
                    } else if (tkey == "acme") {
                        CHECK_OR_NULLOPT(load(tvalue, "acme", service.tls->acme));
                    } else {
                        slog::error("Invalid key '", tkey, "'");
                        return std::nullopt;
                    }
                }
                const auto enough = service.tls->acme || (service.tls->chain && service.tls->key);
                const auto tooMuch = service.tls->acme && (service.tls->chain || service.tls->key);
                if (!enough || tooMuch) {
                    slog::error("Define either both 'chain' and 'key' or only 'acme' in 'tls'");
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
            int64_t qs = 0;
            if (!load(value, "io_queue_size", qs)) {
                return false;
            }
            if (qs < 1 || qs > 4096 || !isPowerOfTwo(qs)) {
                slog::error("'io_queue_size' must be power of two in [1, 4096]");
                return false;
            }
            copy.ioQueueSize = static_cast<size_t>(qs);
        } else if (key == "io_submission_queue_polling") {
            if (!load(value, "io_submission_queue_polling", copy.ioSubmissionQueuePolling)) {
                return false;
            }
        } else if (key == "services") {
            const auto services = loadServices(value);
            if (!services) {
                return false;
            }
            copy.services = *services;
            servicesFound = true;
#ifdef TLS_SUPPORT_ENABLED
        } else if (key == "acme") {
            if (!value.isDictionary()) {
                slog::error("'acme' must be a dictionary");
                return false;
            }
            for (const auto& [akey, avalue] : value.asDictionary()) {
                if (copy.acme.count(akey)) {
                    slog::error("Duplicate key '", akey,
                        "' in 'acme'. Only one acme instance per domain allowed.");
                    return false;
                }
                auto acme = loadAcme(akey, avalue);
                if (!acme) {
                    return false;
                }
                copy.acme.emplace(akey, std::move(*acme));
            }
#endif
        } else {
            slog::error("Invalid key '", key, '"');
            return false;
        }
    }

#ifdef TLS_SUPPORT_ENABLED
    for (const auto& service : copy.services) {
        if (service.tls && service.tls->acme && copy.acme.count(*service.tls->acme) == 0) {
            slog::error("Invalid reference to acme object '", *service.tls->acme, "'");
            return false;
        }
    }
#endif

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
