#include "util.hpp"

#include <cstdio>
#include <memory>
#include <system_error>

#include <arpa/inet.h>
#include <sys/stat.h>

#include "log.hpp"
#include "metrics.hpp"
#include "string.hpp"

std::optional<IpPort> IpPort::parse(std::string_view str)
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

std::string errnoToString(int err)
{
    return std::make_error_code(static_cast<std::errc>(err)).message();
}

std::optional<uint32_t> parseIpAddress(const std::string& str)
{
    ::in_addr addr;
    const auto res = ::inet_aton(str.c_str(), &addr);
    if (res == 0) {
        return std::nullopt;
    }
    return addr.s_addr;
}

std::optional<std::string> readFile(const std::string& path)
{
    const auto timeHandle = Metrics::get().fileReadDuration.labels(path).time();
    auto f = std::unique_ptr<FILE, decltype(&std::fclose)>(
        std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!f) {
        slog::error("Could not open file: '", path, "'");
        return std::nullopt;
    }

    const auto fd = ::fileno(f.get());
    if (fd == -1) {
        slog::error("Could not retrieve file descriptor for file: '", path, "'");
        return std::nullopt;
    }

    struct ::stat st;
    if (::fstat(fd, &st)) {
        slog::error("Could not stat file: '", path, "'");
        return std::nullopt;
    }

    // fopen-ing a directory in read-only mode will actually not fail!
    // And it will return a size of 0x7fffffffffffffff, which is bad.
    if (!S_ISREG(st.st_mode)) {
        slog::error("'", path, "' is not a regular file");
        return std::nullopt;
    }

    if (std::fseek(f.get(), 0, SEEK_END) != 0) {
        slog::error("Error seeking to end of file: '", path, "'");
        return std::nullopt;
    }
    const auto size = std::ftell(f.get());
    if (size < 0) {
        slog::error("Error getting size of file: '", path, "'");
        return std::nullopt;
    }
    if (std::fseek(f.get(), 0, SEEK_SET) != 0) {
        slog::error("Error seeking to start of file: '", path, "'");
        return std::nullopt;
    }
    std::string buf(size, '\0');
    if (std::fread(buf.data(), 1, size, f.get()) != static_cast<size_t>(size)) {
        slog::error("Error reading file: '", path, "'");
        return std::nullopt;
    }
    return buf;
}
