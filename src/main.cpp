#include "config.hpp"
#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "router.hpp"
#include "server.hpp"

using namespace std::literals;

class FileCache {
public:
    // As this server is fully single-threaded, we can get away with returning a reference
    // because the reference might only be invalidated after the handler that is using it
    // has finished. If this server was multi-threaded we should return shared_ptr here instead.
    // If std::optional<T&> was a thing, I would return that instead.
    const std::string* get(const std::string& path)
    {
        const auto it = entries_.find(path);
        if (it == entries_.end()) {
            const auto content = readFile(path);
            if (!content) {
                return nullptr;
            }
            const auto res = entries_.emplace(path, Entry { path, *content });
            return &res.first->second.contents;
        }
        return &it->second.contents;
    }

private:
    static std::optional<std::string> readFile(const std::string& path)
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

    struct Entry {
        std::string path;
        std::string contents;
    };

    std::unordered_map<std::string, Entry> entries_;
};

int main()
{
    std::cout << "Starting HTTP server.." << std::endl;
    const auto& config = Config::get();
    std::cout << "listenPort: " << config.listenPort << std::endl;
    std::cout << "listenBacklog: " << config.listenBacklog << std::endl;
    std::cout << "ioQueueSize: " << config.ioQueueSize << std::endl;
    std::cout << "readAmount: " << config.readAmount << std::endl;
    std::cout << "singleReadTimeoutMs: " << config.singleReadTimeoutMs << std::endl;
    std::cout << "fullReadTimeoutMs: " << config.fullReadTimeoutMs << std::endl;
    std::cout << "maxUrlLength: " << config.maxUrlLength << std::endl;
    std::cout << "maxRequestSize: " << config.maxRequestSize << std::endl;
    std::cout << "defaultRequestSize: " << config.defaultRequestSize << std::endl;

    IoQueue io(config.ioQueueSize);

    FileCache fileCache;

    Router router;

    router.route("/", Method::Get,
        [](const Request&, const Router::RouteParams&) -> Response { return "Hello!"s; });

    router.route("/foo", Method::Get,
        [](const Request&, const Router::RouteParams&) -> Response { return "This is foo"s; });

    router.route("/headers", [](const Request& req, const Router::RouteParams&) -> Response {
        std::string s;
        s.reserve(1024);
        for (const auto& [name, value] : req.headers.getEntries()) {
            s.append("'" + std::string(name) + "' = '" + std::string(value) + "'\n");
        }
        return s;
    });

    router.route("/users/:uid", [](const Request&, const Router::RouteParams& params) -> Response {
        return "User #'" + std::string(params.at("uid")) + "'";
    });

    router.route(
        "/users/:uid/name", [](const Request&, const Router::RouteParams& params) -> Response {
            return "User name for #'" + std::string(params.at("uid")) + "'";
        });

    router.route("/users/:uid/friends/:fid",
        [](const Request&, const Router::RouteParams& params) -> Response {
            return "Friend #'" + std::string(params.at("fid")) + "' for user '"
                + std::string(params.at("uid")) + "'";
        });

    router.route("/users/:uid/files/:path*",
        [](const Request&, const Router::RouteParams& params) -> Response {
            return "File '" + std::string(params.at("path")) + "' for user '"
                + std::string(params.at("uid")) + "'";
        });

    router.route("/file/:path*",
        [&fileCache](const Request&, const Router::RouteParams& params) -> Response {
            const auto f = fileCache.get(std::string(params.at("path")));
            if (!f) {
                return Response(StatusCode::NotFound, "Not Found");
            }
            return *f;
        });

    Server server(io, router);
    server.start();
}
