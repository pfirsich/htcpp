#include "server.hpp"

#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.hpp"

Server::Server()
    : io_(Config::get().ioQueueSize)
    , listenSocket_(createTcpListenSocket(
          Config::get().listenPort, Config::get().listenAddress, Config::get().listenBacklog))
{
    if (listenSocket_ == -1) {
        std::cerr << "Could not create listen socket: "
                  << std::make_error_code(static_cast<std::errc>(errno)).message() << std::endl;
        std::exit(1);
    }
};

void Server::start()
{
    accept();
    io_.run();
}

void Server::route(std::string_view pattern, std::function<Response(const Request&)> handler)
{
    routes_.push_back(Route { Route::Pattern::parse(pattern), Method::Get, std::move(handler) });
}

void Server::route(
    std::string_view pattern, Method method, std::function<Response(const Request&)> handler)
{
    routes_.push_back(Route { Route::Pattern::parse(pattern), method, std::move(handler) });
}

Server::Route::Pattern Server::Route::Pattern::parse(std::string_view str)
{
    Pattern pattern { std::string(str), {} };
    for (const auto& part : split(str, '/')) {
        if (!part.empty() && part[0] == ':') {
            if (part.back() == '*') {
                pattern.parts.push_back(
                    Part { Part::Type::PlaceholderPath, part.substr(1, part.size() - 2) });
            } else {
                pattern.parts.push_back(Part { Part::Type::Placeholder, part.substr(1) });
            }
        } else {
            pattern.parts.push_back(Part { Part::Type::Literal, part });
        }
    }
    return pattern;
}

std::optional<std::unordered_map<std::string_view, std::string_view>> Server::Route::Pattern::match(
    std::string_view urlPath) const
{
    size_t cursor = 0;
    std::unordered_map<std::string_view, std::string_view> params;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (parts[i].type == Part::Type::Literal || parts[i].type == Part::Type::Placeholder) {
            const auto slash = std::min(urlPath.find('/', cursor), urlPath.size());
            const auto urlPart = urlPath.substr(cursor, slash - cursor);
            if (parts[i].type == Part::Type::Literal) {
                if (parts[i].str != urlPart) {
                    return std::nullopt;
                }
            } else {
                assert(parts[i].type == Part::Type::Placeholder);
                params[parts[i].str] = urlPart;
            }
            // We have reached the end of urlPath, but there are pattern parts left
            if (cursor >= urlPath.size() && i < parts.size() - 1) {
                return std::nullopt;
            }
            cursor = slash + 1;
        } else {
            assert(parts[i].type == Part::Type::PlaceholderPath);
            params[parts[i].str] = urlPath.substr(cursor);
            return params;
        }
    }
    // Not the whole urlPath has been consumed => no complete match
    if (cursor < urlPath.size()) {
        return std::nullopt;
    }
    return params;
}

Server::Connection::Connection(IoQueue& io, int fd, const std::vector<Server::Route>& routes)
    : io_(io)
    , fd_(fd)
    , routes_(routes)
{
    request_.reserve(Config::get().defaultRequestSize);
}

void Server::Connection::start()
{
    readSome();
}

void Server::Connection::close()
{
    io_.close(fd_, [self = shared_from_this()](std::error_code /*ec*/) {});
}

void Server::Connection::respondAndClose(std::string_view response)
{
    io_.send(fd_, response.data(), response.size(),
        [this, self = shared_from_this()](std::error_code /*ec*/, int /*sent*/) { close(); });
}

void Server::Connection::processRequest(std::string_view requestStr)
{
    auto request = Request::parse(requestStr);
    if (!request) {
        respondAndClose(badRequest);
        return;
    }
    for (const auto& route : routes_) {
        auto params = route.pattern.match(request->url.path);
        if (params) {
            request->params = std::move(*params);
            auto resp = route.handler(*request);
            if (resp.body.size() > 0) {
                resp.headers.set("Content-Length", std::to_string(resp.body.size()));
            }
            respondAndClose(resp.string());
            return;
        }
    }
    // No matching route
    respondAndClose("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
}

void Server::Connection::readSome()
{
    const auto readAmount = Config::get().readAmount;
    const auto currentSize = request_.size();
    request_.append(readAmount, '\0');
    auto buf = request_.data() + currentSize;
    io_.recv(fd_, buf, readAmount,
        [this, self = shared_from_this(), readAmount](std::error_code ec, int readBytes) {
            if (ec) {
                std::cerr << "Error in read: " << ec.message() << std::endl;
                close();
            } else {
                if (readBytes > 0) { // res = 0 => no data left to read
                    request_.resize(request_.size() - readAmount + readBytes);
                }

                // Done reading
                if (readBytes == 0 || static_cast<size_t>(readBytes) < readAmount) {
                    processRequest(request_);
                } else {
                    readSome();
                }
            }
        });
}

Fd Server::createTcpListenSocket(uint16_t listenPort, uint32_t listenAddr, int backlog)
{
    Fd fd { ::socket(AF_INET, SOCK_STREAM, 0) };
    if (fd == -1)
        return fd;

    sockaddr_in addr;
    ::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(listenAddr);
    addr.sin_port = htons(listenPort);

    const int reuse = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        return Fd {};
    }

    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        return Fd {};
    }

    if (::listen(fd, backlog) == -1) {
        return Fd {};
    }

    return fd;
}

void Server::accept()
{
    // In the past there was a bug, where too many concurrent requests would fill up the SQR
    // with reads and writes so that it would run full and you could not add an accept SQE.
    // Essentially too high concurrency would push out the accept task and the server would stop
    // accepting connections.
    // For some reason I cannot reproduce it anymore. Maybe *something* has changed with a newer
    // kernel, but I can't imagine what that would be.
    // I will fix it anyway, because it should be dead code, if everything goes right anyways.
    // So essentially we *force* an accept SQE into the SQR by retrying again and again.
    // This is a busy loop, because we *really* want to get that accept into the SQR and we
    // don't have to worry about priority inversion (I think) because it's the kernel that's
    // consuming the currently present items.
    bool added = false;
    while (!added) {
        added = io_.accept(
            listenSocket_, nullptr, [this](std::error_code ec, int fd) { handleAccept(ec, fd); });
    }
}

void Server::handleAccept(std::error_code ec, int fd)
{
    if (ec) {
        std::cerr << "Error: " << ec.message() << std::endl;
        std::exit(1);
    }

    auto conn = std::make_shared<Connection>(io_, fd, routes_);
    conn->start();

    accept();
}
