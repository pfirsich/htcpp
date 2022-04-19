#pragma once

#include <memory>
#include <string>
#include <vector>

#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"

class Server {
public:
    Server();

    void start();

    void route(std::string_view pattern, std::function<Response(const Request&)> handler);

    void route(
        std::string_view pattern, Method method, std::function<Response(const Request&)> handler);

private:
    struct Route {
        struct Pattern {
            struct Part {
                enum class Type {
                    Literal,
                    Placeholder,
                    PlaceholderPath,
                };

                Type type;
                std::string_view str;
            };

            std::string pattern;
            std::vector<Part> parts;

            static Pattern parse(std::string_view str);

            std::optional<std::unordered_map<std::string_view, std::string_view>> match(
                std::string_view urlPath) const;
        };

        Pattern pattern;
        Method method;
        std::function<Response(const Request&)> handler;
    };

    // A connection will have ownership of itself and decide on its own when it's time to be
    // destroyed
    class Connection : public std::enable_shared_from_this<Connection> {
    public:
        Connection(IoQueue& io, int fd, const std::vector<Route>& routes);

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
        int fd_;
        std::string request_;
        const std::vector<Route>& routes_;
    };

    static Fd createTcpListenSocket(
        uint16_t listenPort, uint32_t listenAddr = INADDR_ANY, int backlog = 1024);

    void accept();

    void handleAccept(std::error_code ec, int fd);

    IoQueue io_;
    Fd listenSocket_;
    std::vector<Route> routes_;
};
