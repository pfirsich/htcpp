#pragma once

#include <optional>
#include <string>
#include <unordered_map>

#include "filewatcher.hpp"
#include "ioqueue.hpp"

// TODO: I should probably reload files in another thread, so it doesn't slow down the server itself
// but block on the first load.
class FileCache {
public:
    struct Entry {
        enum class State { Outdated, UpToDate };

        std::string path;
        std::optional<std::string> contents = std::nullopt;
        std::string eTag = "";
        std::string lastModified = "";
        State state = State::Outdated;

        bool reload();
    };

    FileCache(IoQueue& io);

    // As this server is fully single-threaded, we can get away with returning a reference
    // because the reference might only be invalidated after the handler that is using it
    // has finished. If this server was multi-threaded we should return shared_ptr here instead.
    // If std::optional<T&> was a thing, I would return that instead.
    const Entry* get(const std::string& path);

private:
    IoQueue& io_;
    FileWatcher fileWatcher_;
    std::unordered_map<std::string, Entry> entries_;
};
