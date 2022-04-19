#pragma once

#include <string_view>
#include <vector>

// NO. LOCALES.
char toLower(char c);

bool ciEqual(std::string_view a, std::string_view b);

bool isHttpWhitespace(char c);

std::vector<std::string_view> split(std::string_view str, char delim);
