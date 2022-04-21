#pragma once

#include <optional>
#include <string>
#include <unordered_map>

#include "ioqueue.hpp"

// TODO: I should probably reload files in another thread, so it doesn't slow down the server itself
// but block on the first load.
class FileCache {
public:
    FileCache(IoQueue& io);

    // As this server is fully single-threaded, we can get away with returning a reference
    // because the reference might only be invalidated after the handler that is using it
    // has finished. If this server was multi-threaded we should return shared_ptr here instead.
    // If std::optional<T&> was a thing, I would return that instead.
    const std::string* get(const std::string& path);

private:
    static std::optional<std::string> readFile(const std::string& path);

    struct File {
        std::string path;
        std::optional<std::string> contents = std::nullopt;
        bool dirty = true;

        void reload();
    };

    IoQueue& io_;
    std::unordered_map<std::string, File> files_;
};
