#pragma once

#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// NO. LOCALES.
char toLower(char c);

bool ciEqual(std::string_view a, std::string_view b);

bool isHttpWhitespace(char c);
bool isDigit(char c);

std::vector<std::string_view> split(std::string_view str, char delim);

std::string_view httpTrim(std::string_view str);

bool startsWith(std::string_view str, std::string_view start);
bool endsWith(std::string_view str, std::string_view end);

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

std::string pathJoin(std::string_view a, std::string_view b);

template <typename Container>
std::string join(const Container& container, std::string_view delim = ", ")
{
    std::string ret;
    bool first = true;
    for (const auto& elem : container) {
        if (!first) {
            ret.append(delim);
        }
        first = false;
        ret.append(elem);
    }
    return ret;
}

std::string rjust(std::string_view str, size_t length, char ch);
