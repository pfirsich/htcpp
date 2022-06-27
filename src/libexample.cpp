#include <cpprom/cpprom.hpp>

#include "filecache.hpp"
#include "router.hpp"
#include "tcp.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

using namespace std::literals;

static std::string getMimeType(std::string fileExt)
{
    static std::unordered_map<std::string, std::string> mimeTypes {
        { "jpg", "image/jpeg" },
        { "html", "text/html" },
    };
    const auto it = mimeTypes.find(fileExt);
    if (it == mimeTypes.end()) {
        return "text/plain";
    }
    return it->second;
}

int main()
{
    slog::init(slog::Severity::Debug);

    IoQueue io;

    FileCache fileCache(io);

    Router router;

    router.route(Method::Get, "/",
        [](const Request&, const Router::RouteParams&) -> Response { return "Hello!"s; });

    router.route(Method::Get, "/number/:num",
        [](const Request&, const Router::RouteParams& params) -> Response {
            return "Number: "s + std::string(params.at("num"));
        });

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
            const auto path = params.at("path");
            const auto f = fileCache.get(std::string(path));
            if (!f) {
                return Response(StatusCode::NotFound, "Not Found");
            }
            const auto extDelim = path.find_last_of('.');
            const auto ext = path.substr(std::min(extDelim + 1, path.size()));
            return Response(*f, getMimeType(std::string(ext)));
        });

    router.route("/metrics",
        [&io](const Request&, const Router::RouteParams&, std::shared_ptr<Responder> responder) {
            io.async<Response>(
                []() {
                    return Response(
                        cpprom::Registry::getDefault().serialize(), "text/plain; version=0.0.4");
                },
                [responder = std::move(responder)](
                    std::error_code ec, Response&& response) mutable {
                    assert(!ec);
                    responder->respond(std::move(response));
                });
        });

    Server<TcpConnectionFactory> server(io, TcpConnectionFactory {}, router);
    server.start();
    io.run();

    return 0;
}
