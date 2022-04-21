#include "filecache.hpp"

#include <memory>

FileCache::FileCache(IoQueue& io)
    : io_(io)
{
}

// As this server is fully single-threaded, we can get away with returning a reference
// because the reference might only be invalidated after the handler that is using it
// has finished. If this server was multi-threaded we should return shared_ptr here instead.
// If std::optional<T&> was a thing, I would return that instead.
const std::string* FileCache::get(const std::string& path)
{
    auto it = files_.find(path);
    if (it == files_.end()) {
        it = files_.emplace(path, File { path }).first;
    }

    if (it->second.dirty) {
        it->second.reload();
    }

    if (!it->second.contents) {
        return nullptr;
    }
    return &*it->second.contents;
}

std::optional<std::string> FileCache::readFile(const std::string& path)
{
    auto f = std::unique_ptr<FILE, decltype(&std::fclose)>(
        std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!f) {
        std::cerr << "Could not open file '" << path << "'" << std::endl;
        return std::nullopt;
    }
    if (std::fseek(f.get(), 0, SEEK_END) != 0) {
        std::cerr << "Error seeking to end of '" << path << "'" << std::endl;
        return std::nullopt;
    }
    const auto size = std::ftell(f.get());
    if (size < 0) {
        std::cerr << "Error getting size of '" << path << "'" << std::endl;
        return std::nullopt;
    }
    if (std::fseek(f.get(), 0, SEEK_SET) != 0) {
        std::cerr << "Error seeking to start of '" << path << "'" << std::endl;
        return std::nullopt;
    }
    std::string buf(size, '\0');
    if (std::fread(buf.data(), 1, size, f.get()) != static_cast<size_t>(size)) {
        std::cerr << "Error reading file '" << path << "'" << std::endl;
        return std::nullopt;
    }
    return buf;
}

void FileCache::File::reload()
{
    std::cout << "reload " << path << std::endl;
    const auto cont = readFile(path);
    if (cont) {
        contents = *cont;
    }
    // Reset dirty either way, so that we don't repeatedly try to load a file that e.g. does
    // not exist.
    // We wait for another modification before we try again.
    dirty = false;
}
