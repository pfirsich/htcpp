#include "string.hpp"

#include <array>
#include <cassert>

constexpr std::array<char, 256> getToLowerTable()
{
    std::array<char, 256> table = {};
    for (size_t i = 0; i < 256; ++i) {
        table[i] = static_cast<char>(static_cast<uint8_t>(i));
        if (i >= 'A' && i <= 'Z') {
            table[i] -= 'A' - 'a';
        }
    }
    return table;
}

// No fucking LOCALES, DUDE (FUCK THEEEEEM)
char toLower(char c)
{
    static auto table = getToLowerTable();
    return table[static_cast<uint8_t>(c)];
}

bool ciEqual(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (toLower(a[i]) != toLower(b[i])) {
            return false;
        }
    }
    return true;
}

bool isHttpWhitespace(char c)
{
    return c == ' ' || c == '\t';
}

bool isDigit(char c)
{
    return c >= '0' && c <= '9';
}

std::vector<std::string_view> split(std::string_view str, char delim)
{
    std::vector<std::string_view> parts;
    size_t i = 0;
    while (i < str.size()) {
        const auto delimPos = str.find(delim, i);
        if (delimPos == std::string_view::npos) {
            break;
        }
        parts.push_back(str.substr(i, delimPos - i));
        i = delimPos + 1;
    }
    parts.push_back(str.substr(i));
    return parts;
}

std::string_view httpTrim(std::string_view str)
{
    if (str.empty()) {
        return str;
    }

    size_t start = 0;
    while (start < str.size() && isHttpWhitespace(str[start])) {
        start++;
    }
    if (start == str.size()) {
        return str.substr(start, 0);
    }
    assert(start < str.size());

    auto end = str.size() - 1;
    while (end > start && isHttpWhitespace(str[end])) {
        end--;
    }

    return str.substr(start, end + 1 - start);
}

bool startsWith(std::string_view str, std::string_view start)
{
    return str.substr(0, start.size()) == start;
}

bool endsWith(std::string_view str, std::string_view end)
{
    return str.substr(str.size() - end.size()) == end;
}

std::string pathJoin(std::string_view a, std::string_view b)
{
    assert(!a.empty());
    std::string ret(a);
    if (a.back() != '/') {
        ret.push_back('/');
    }
    ret.append(b);
    return ret;
}
