#include "config.hpp"
#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "server.hpp"

using namespace std::literals;

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

    Server http;

    http.route("/", Method::Get, [](const Request&) -> Response { return "Hello!"s; });

    http.route("/foo", Method::Get, [](const Request&) -> Response { return "This is foo"s; });

    http.route("/headers", [](const Request& req) -> Response {
        std::string s;
        s.reserve(1024);
        for (const auto& [name, value] : req.headers.getEntries()) {
            s.append("'" + std::string(name) + "' = '" + std::string(value) + "'\n");
        }
        return s;
    });

    http.route("/users/:uid", [](const Request& req) -> Response {
        return "User #'" + std::string(req.params.at("uid")) + "'";
    });

    http.route("/users/:uid/name", [](const Request& req) -> Response {
        return "User name for #'" + std::string(req.params.at("uid")) + "'";
    });

    http.route("/users/:uid/friends/:fid", [](const Request& req) -> Response {
        return "Friend #'" + std::string(req.params.at("fid")) + "' for user '"
            + std::string(req.params.at("uid")) + "'";
    });

    http.route("/users/:uid/files/:path*", [](const Request& req) -> Response {
        return "File '" + std::string(req.params.at("path")) + "' for user '"
            + std::string(req.params.at("uid")) + "'";
    });

    http.start();
}
