#include "filecache.hpp"

#include <memory>

#include <sys/stat.h>

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
const FileCache::Entry* FileCache::get(const std::string& path)
{
    Metrics::get().fileCacheQueries.labels(path).inc();
    auto it = entries_.find(path);
    if (it == entries_.end()) {
        it = entries_.emplace(path, Entry { path }).first;
        fileWatcher_.watch(path, [this](std::error_code ec, std::string_view path) {
            if (ec) {
                entries_.erase(std::string(path));
                return;
            }
            slog::info("file changed: '", path, "'");
            entries_.at(std::string(path)).dirty = true;
        });
    }

    if (it->second.dirty) {
        it->second.reload();
        // Reset dirty either way (error or not), so that we don't repeatedly try to load a file
        // that e.g. does not exist.
        // We wait for another modification before we try again.
        it->second.dirty = false;
    } else {
        Metrics::get().fileCacheHits.labels(path).inc();
    }

    if (!it->second.contents) {
        Metrics::get().fileCacheFailures.labels(path).inc();
        return nullptr;
    }
    return &it->second;
}

namespace {
// I do this myself, because I don't want to worry about locales
std::optional<std::string> formatTm(const std::tm* tm)
{
    constexpr std::array weekDays = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    constexpr std::array months
        = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    if (tm->tm_wday < 0 || tm->tm_wday > 6) {
        slog::error("Weekday is out of range: ", tm->tm_wday);
        return std::nullopt;
    }
    if (tm->tm_mon < 0 || tm->tm_mon > 11) {
        slog::error("Month is out of range: ", tm->tm_mon);
        return std::nullopt;
    }
    // https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1
    // example: Sat, 23 Apr 2022 23:22:48 GMT
    char buf[32];
    const auto res = std::snprintf(buf, sizeof(buf), "%s, %02d %s %d %02d:%02d:%02d GMT",
        weekDays[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900, tm->tm_hour,
        tm->tm_min, tm->tm_sec);
    if (res < 0) {
        slog::error("Could not format time");
        return std::nullopt;
    }
    return std::string(buf);
}
}

void FileCache::Entry::reload()
{
    slog::info("reload file: '", path, "'");
    const auto cont = readFile(path);
    if (!cont) {
        // Error already logged
        return;
    }

    // Using mtime and size is very popular. This is used by Apache, binserve, Caddy, lighthttpd,
    // and nginx. Sometimes the inode is included, but I don't think it's very necessary and can
    // lead to problems if the files are served from multiple instances of a server (e.g. behind a
    // load balancer):
    // https://github.com/caddyserver/caddy/pull/1435/files
    // https://serverfault.com/a/690374

    // Also there is a very improbable vulnerabilty in including the inode, which I have no trouble
    // ignoring, but I don't want anyone to *ever* open an issue for this, so I just leave it out
    // from the start:
    // https://www.pentestpartners.com/security-blog/vulnerabilities-that-arent-etag-headers/

    // https://www.rfc-editor.org/rfc/rfc7232#section-2.1 distinguishes between strong and weak
    // validators and this is not actually a strong validator, but it is still specified as a strong
    // validator, because weak don't do anything for partial content (which I do not support *yet*).
    // Nginx and Caddy also do this.
    // There is a TODO item for optionally using a cryptographic hash for the ETag.

    // This is kind of race-ey, but I don't think there is much we can do reasonably.
    // One way would be to read the file multiple times to check if the content changed after the
    // stat, which I consider unreasonable.
    struct ::stat st;
    const auto statRes = ::stat(path.c_str(), &st);
    if (statRes != 0) {
        slog::error("Could not stat '", path, "': ", errnoToString(errno));
        return;
    }

    // https://www.rfc-editor.org/rfc/rfc7232#section-2.3
    // The ETag can be any number of double quoted characters in {0x21, 0x23-0x7E, 0x80-0xFF}
    char eTagBuf[64] = { 0 }; // at most 32 chars (8 bytes and 8 bytes with 2 chars per byte)
    // long st_size, long int st_mtime
    if (std::snprintf(eTagBuf, sizeof(eTagBuf), "\"%lx-%lx\"", st.st_mtime, st.st_size) < 0) {
        slog::error("Could not format ETag");
        return;
    }

    const auto tm = std::gmtime(&st.st_mtime);
    const auto lm = formatTm(tm);
    if (!lm) {
        // Already logged
        return;
    }

    contents = *cont;
    eTag = eTagBuf;
    lastModified = *lm;
}
