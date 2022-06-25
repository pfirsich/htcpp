#include "util.hpp"

#include <system_error>

#include <arpa/inet.h>

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
