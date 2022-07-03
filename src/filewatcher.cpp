#include "filewatcher.hpp"

#include <sys/poll.h>
#include <unistd.h>

#include "log.hpp"
#include "util.hpp"

FileWatcher::FileWatcher(IoQueue& io)
    : io_(io)
    , inotifyFd_(::inotify_init())
{
    if (inotifyFd_ < 0) {
        slog::fatal("inotify_init failed: ", errnoToString(errno));
        std::exit(1);
    }

    read();
}

FileWatcher::~FileWatcher()
{
    for (const auto& [path, watch] : dirWatches_) {
        ::inotify_rm_watch(inotifyFd_, watch.wd);
    }
    dirWatches_.clear();
}

bool FileWatcher::watch(
    std::string_view path, std::function<void(std::error_code, std::string_view)> callback)
{
    const auto lastSep = path.rfind("/");
    const auto dirPath = lastSep == std::string_view::npos ? std::string(".")
                                                           : std::string(path.substr(0, lastSep));
    auto it = dirWatches_.find(dirPath);
    if (it == dirWatches_.end()) {
        const auto wd = ::inotify_add_watch(inotifyFd_, dirPath.c_str(), IN_CLOSE_WRITE);
        if (wd < 0) {
            slog::error("Could not watch directory '", dirPath, "': ", errnoToString(errno));
            return false;
        }
        it = dirWatches_.emplace(dirPath, DirWatch { dirPath, wd }).first;
    }
    auto& dirWatch = it->second;
    const auto filename = lastSep == std::string_view::npos ? std::string(path)
                                                            : std::string(path.substr(lastSep + 1));
    if (dirWatch.fileWatches.count(filename)) {
        slog::error("Already watching ", path);
        return false;
    }
    dirWatch.fileWatches.emplace(
        filename, FileWatch { std::string(path), filename, std::move(callback) });
    return true;
}

void FileWatcher::read()
{
    io_.read(inotifyFd_, eventBuffer_, eventBufferLen,
        [this](std::error_code ec, int readBytes) { onRead(ec, readBytes); });
}

void FileWatcher::onRead(std::error_code ec, int readBytes)
{
    if (ec) {
        slog::error("Error reading inotify fd: ", ec.message());
        read();
        return;
    }

    long i = 0;
    while (i < readBytes) {
        const auto event = reinterpret_cast<const ::inotify_event*>(&eventBuffer_[i]);

        const auto dit = std::find_if(dirWatches_.begin(), dirWatches_.end(),
            [event](const auto& entry) { return entry.second.wd == event->wd; });
        assert(dit != dirWatches_.end());
        auto& dirWatch = dit->second;

        if (event->mask & IN_IGNORED) {
            // rewatch
            slog::debug("Rewatch '", dirWatch.path, "'");
            dirWatch.wd = ::inotify_add_watch(inotifyFd_, dirWatch.path.c_str(), IN_CLOSE_WRITE);
            if (dirWatch.wd < 0) {
                slog::error(
                    "Could not rewatch directory '", dirWatch.path, "': ", errnoToString(errno));
                for (const auto& [filename, fileWatch] : dirWatch.fileWatches) {
                    fileWatch.callback(
                        std::make_error_code(static_cast<std::errc>(errno)), fileWatch.path);
                }
                dirWatches_.erase(dirWatch.path);
            }
        } else if (event->len > 0) {
            assert(event->mask & IN_CLOSE_WRITE);
            const auto filename = std::string(event->name);
            const auto fit = dirWatch.fileWatches.find(filename);
            if (fit != dirWatch.fileWatches.end()) {
                fit->second.callback(std::error_code(), fit->second.path);
            }
        }
        i += sizeof(inotify_event) + event->len;
    }
    // If the following assert fails, we have read an event partially. This should not happen.
    assert(i == readBytes);

    read();
}
