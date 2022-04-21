#pragma once

#include <memory>
#include <string>
#include <vector>

#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"

class Server {
public:
    Server(IoQueue& io, std::function<Response(const Request&)> handler);

    void start();

private:
    // A connection will have ownership of itself and decide on its own when it's time to be
    // destroyed
    class Connection : public std::enable_shared_from_this<Connection> {
    public:
        Connection(IoQueue& io, std::function<Response(const Request&)>& handler, int fd);

        ~Connection() = default;

        void start();

        void close();

    private:
        static constexpr std::string_view badRequest
            = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";

        void respondAndClose(std::string_view response);

        void processRequest(std::string_view requestStr);

        void readSome();

        IoQueue& io_;
        std::function<Response(const Request&)>& handler_;
        int fd_;
        std::string request_;
    };

    static Fd createTcpListenSocket(
        uint16_t listenPort, uint32_t listenAddr = INADDR_ANY, int backlog = 1024);

    void accept();

    void handleAccept(std::error_code ec, int fd);

    IoQueue& io_;
    Fd listenSocket_;
    std::function<Response(const Request&)> handler_;
};
