#include "config.hpp"

Config& Config::get()
{
    static Config config;
    return config;
}
