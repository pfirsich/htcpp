#pragma once

#include <charconv>
#include <optional>
#include <string_view>
#include <vector>

// NO. LOCALES.
char toLower(char c);

bool ciEqual(std::string_view a, std::string_view b);

bool isHttpWhitespace(char c);

std::vector<std::string_view> split(std::string_view str, char delim);

template <typename T = uint64_t>
std::optional<T> parseInt(std::string_view str, int base = 10)
{
    const auto first = str.data();
    const auto last = first + str.size();
    T value;
    const auto res = std::from_chars(first, last, value, base);
    if (res.ec == std::errc() && res.ptr == last) {
        return value;
    } else {
        return std::nullopt;
    }
}
