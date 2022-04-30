#include "config.hpp"

#include <cstdlib>
#include <limits>
#include <optional>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "log.hpp"
#include "string.hpp"

namespace {
std::optional<std::string> getEnv(const char* name)
{
    const auto var = std::getenv(name);
    if (!var) {
        return std::nullopt;
    }
    return std::string(var);
}

template <typename T>
void loadIntVar(T& var, const char* envVarName, T min = std::numeric_limits<T>::min(),
    T max = std::numeric_limits<T>::max())
{
    const auto envVar = getEnv(envVarName);
    if (envVar) {
        const auto val = parseInt<T>(*envVar);
        if (val) {
            if (*val < min || *val > max) {
                slog::error("Value for '", envVarName, "' is out of range (", min, "-", max,
                    "). Using default value: ", var);
                return;
            }
            var = *val;
        } else {
            slog::error("Could not parse environment variable '", envVarName,
                "'. Using default value: ", var);
        }
    }
}

void loadBoolVar(bool& var, const char* envVarName)
{
    const auto envVar = getEnv(envVarName);
    if (envVar) {
        if (*envVar == "0") {
            var = false;
        } else {
            var = true;
            if (*envVar != "1") {
                slog::warning("Unexpected value for '", envVarName, "'. Use '1' instead.");
            }
        }
    }
}

void loadAddressVar(uint32_t& var, const char* envVarName)
{
    const auto envVar = getEnv(envVarName);
    if (envVar) {
        ::in_addr addr;
        const auto res = ::inet_aton(envVar->c_str(), &addr);
        if (res == 0) {
            slog::error("Invalid address string for '", envVarName,
                "'. Using default value: ", ::inet_ntoa(::in_addr { var }));
            return;
        }
        var = addr.s_addr;
    }
}
}

Config& Config::get()
{
    static Config config;
    static bool initialized = false;
    if (!initialized) {
        loadIntVar(config.listenPort, "URHTS_LISTEN_PORT");
        loadIntVar(config.listenBacklog, "URHTS_LISTEN_BACKLOG");
        // If this is not a power of two, it will crash anyways
        loadIntVar(config.ioQueueSize, "URHTS_IO_QUEUE_SIZE", 1ul, 4096ul);
        loadIntVar(config.readAmount, "URHTS_READ_AMOUNT");
        loadIntVar(config.singleReadTimeoutMs, "URHTS_SINGLE_READ_TIMEOUT_MS");
        loadIntVar(config.fullReadTimeoutMs, "URHTS_FULL_READ_TIMEOUT_MS");
        loadIntVar(config.maxUrlLength, "URHTS_MAX_URL_LENGTH");
        loadIntVar(config.maxRequestSize, "URHTS_MAX_REQUEST_SIZE");
        loadIntVar(config.defaultRequestSize, "URHTS_DEFAULT_REQUEST_SIZE");
        loadBoolVar(config.useTls, "URHTS_USE_TLS");
        loadBoolVar(config.accesLog, "URHTS_ACCESS_LOG");
        loadBoolVar(config.debugLogging, "URHTS_DEBUG_LOGGING");
        loadAddressVar(config.listenAddress, "URHTS_LISTEN_ADDRESS");
    }
    initialized = true;
    return config;
}
