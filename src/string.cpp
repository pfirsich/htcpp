#include "string.hpp"

#include <array>

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

bool startsWith(std::string_view str, std::string_view start)
{
    return str.substr(0, start.size()) == start;
}
