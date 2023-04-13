#pragma once

#include <optional>
#include <string>

struct IpPort {
    std::optional<uint32_t> ip;
    uint16_t port;

    static std::optional<IpPort> parse(std::string_view str);
};

std::string errnoToString(int err);
std::optional<uint32_t> parseIpAddress(const std::string& str);
std::optional<std::string> readFile(const std::string& path);

uint64_t nowMillis();
