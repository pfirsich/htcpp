#include "util.hpp"

#include <system_error>

std::string errnoToString(int err)
{
    return std::make_error_code(static_cast<std::errc>(err)).message();
}
