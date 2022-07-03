#include "filecache.hpp"

#include <memory>

#include "log.hpp"
#include "metrics.hpp"
#include "util.hpp"

FileCache::FileCache(IoQueue& io)
    : io_(io)
    , fileWatcher_(io)
{
}

// As this server is fully single-threaded, we can get away with returning a reference
// because the reference might only be invalidated after the handler that is using it
// has finished. If this server was multi-threaded we should return shared_ptr here instead.
// If std::optional<T&> was a thing, I would return that instead.
const std::string* FileCache::get(const std::string& path)
{
    Metrics::get().fileCacheQueries.labels(path).inc();
    auto it = files_.find(path);
    if (it == files_.end()) {
        it = files_.emplace(path, File { path }).first;
        fileWatcher_.watch(path, [this](std::error_code ec, std::string_view path) {
            if (ec) {
                files_.erase(std::string(path));
                return;
            }
            slog::info("file changed: '", path, "'");
            files_.at(std::string(path)).dirty = true;
        });
    }

    if (it->second.dirty) {
        it->second.reload();
    }

    if (!it->second.contents) {
        Metrics::get().fileCacheFailures.labels(path).inc();
        return nullptr;
    }
    return &*it->second.contents;
}

void FileCache::File::reload()
{
    slog::info("reload file: '", path, "'");
    const auto cont = readFile(path);
    if (cont) {
        contents = *cont;
    }
    // Reset dirty either way, so that we don't repeatedly try to load a file that e.g. does
    // not exist.
    // We wait for another modification before we try again.
    dirty = false;
}
