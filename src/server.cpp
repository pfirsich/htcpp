#include "server.hpp"

#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.hpp"

Server::Server(IoQueue& io, std::function<Response(const Request&)> handler)
    : io_(io)
    , listenSocket_(createTcpListenSocket(
          Config::get().listenPort, Config::get().listenAddress, Config::get().listenBacklog))
    , handler_(std::move(handler))
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

Server::Connection::Connection(
    IoQueue& io, std::function<Response(const Request&)>& handler, int fd)
    : io_(io)
    , handler_(handler)
    , fd_(fd)
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
    respondAndClose(handler_(*request).string());
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
                return;
            }

            if (readBytes > 0) {
                request_.resize(request_.size() - readAmount + readBytes);
            }

            // Done reading
            if (readBytes == 0 || static_cast<size_t>(readBytes) < readAmount) {
                processRequest(request_);
            } else {
                readSome();
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
        std::cerr << "Error in accept: " << ec.message() << std::endl;
        return;
    }

    auto conn = std::make_shared<Connection>(io_, handler_, fd);
    conn->start();

    accept();
}
