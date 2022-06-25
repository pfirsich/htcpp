#include <optional>
#include <string>

std::string errnoToString(int err);
std::optional<uint32_t> parseIpAddress(const std::string& str);
