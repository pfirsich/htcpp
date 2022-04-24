#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

#include <sys/inotify.h>

#include "fd.hpp"
#include "ioqueue.hpp"

class FileWatcher {
public:
    FileWatcher(IoQueue& io);

    ~FileWatcher();

    bool watch(std::string_view path, std::function<void(std::string_view path)> callback);

private:
    struct FileWatch {
        std::string path;
        std::string filename;
        std::function<void(std::string_view)> callback;
    };

    struct DirWatch {
        std::string path;
        int wd;
        std::unordered_map<std::string, FileWatch> fileWatches = {};
    };

    void pollInotify();

    void onInotifyReadable(std::error_code ec, int revents);

    IoQueue& io_;
    Fd inotifyFd_;
    std::unordered_map<std::string, DirWatch> dirWatches_;
};