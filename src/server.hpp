#pragma once

#include <memory>
#include <string>
#include <vector>

#include "config.hpp"
#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "log.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

Fd createTcpListenSocket(uint16_t listenPort, uint32_t listenAddr = INADDR_ANY, int backlog = 1024);

class TcpConnection {
public:
    TcpConnection(IoQueue& io, int fd);

    void recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void shutdown(IoQueue::HandlerEc handler);
    void close();

protected:
    IoQueue& io_;
    int fd_;
};

// Maybe I should put the function definitions into server.cpp and instantiate the template
// explicitly for TcpConnection and SslConnection, but I would have to do that in server.cpp
// (meaning I would have to include ssl.hpp), which I don't really like right now.
template <typename Connection>
class Server {
public:
    Server(IoQueue& io, std::function<Response(const Request&)> handler)
        : io_(io)
        , listenSocket_(createTcpListenSocket(
              Config::get().listenPort, Config::get().listenAddress, Config::get().listenBacklog))
        , handler_(std::move(handler))
    {
        if (listenSocket_ == -1) {
            slog::fatal("Could not create listen socket: ", errnoToString(errno));
            std::exit(1);
        }
    };

    void start()
    {
        accept();
        io_.run();
    }

private:
    // A Session will have ownership of itself and decide on its own when it's time to be
    // destroyed
    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(IoQueue& io, int fd, std::function<Response(const Request&)>& handler,
            std::string remoteAddr)
            : connection_(io, fd)
            , handler_(handler)
            , remoteAddr_(std::move(remoteAddr))
        {
            requestBuffer_.reserve(Config::get().defaultRequestSize);
        }

        ~Session() = default;
        Session(const Session&) = default;
        Session(Session&&) = default;
        Session& operator=(const Session&) = default;
        Session& operator=(Session&&) = default;

        void start()
        {
            // readRequests is not part of the constructor and in this separate method, because
            // shared_from_this must not be called until the shared_ptr constructor has completed.
            // You would get a bad_weak_ptr exception in shared_from_this if you called it from the
            // Session constructor.
            requestBuffer_.clear();
            readRequest();
        }

    private:
        void readRequest()
        {
            const auto currentSize = requestBuffer_.size();
            assert(currentSize < Config::get().maxRequestSize);
            const auto readAmount
                = std::min(Config::get().readAmount, Config::get().maxRequestSize - currentSize);
            requestBuffer_.append(readAmount, '\0');
            auto buf = requestBuffer_.data() + currentSize;
            connection_.recv(buf, readAmount,
                // `this->` before `shared_from_this` is necessary or you get an error
                // because of a dependent type lookup.
                [this, self = this->shared_from_this(), readAmount](
                    std::error_code ec, int readBytes) {
                    if (ec) {
                        slog::error("Error in recv: ", ec.message());
                        // Error might be ECONNRESET, EPIPE (from send) or others, where we just
                        // want to close. There might be errors, where shutdown is better, but
                        // especially with SSL almost all errors here require us to NOT shutdown.
                        // Same applies for send below.
                        connection_.close();
                        return;
                    }

                    if (readBytes == 0) {
                        connection_.close();
                        return;
                    }

                    if (readBytes > 0) {
                        requestBuffer_.resize(requestBuffer_.size() - readAmount + readBytes);
                    }

                    if (static_cast<size_t>(readBytes) < readAmount) {
                        // Done reading
                        processRequest(requestBuffer_);
                    } else if (requestBuffer_.size() >= Config::get().maxRequestSize) {
                        respond(
                            "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n", false);
                    } else {
                        readRequest();
                    }
                });
        }

        bool getKeepAlive(const Request& request)
        {
            const auto connectionHeader = request.headers.get("Connection");
            if (connectionHeader) {
                if (connectionHeader->find("close") != std::string_view::npos) {
                    return false;
                }
                // I should check case-insensitively here, but it's always lowercase in practice
                // (everywhere I tried)
                if (connectionHeader->find("keep-alive") != std::string_view::npos) {
                    return true;
                }
            }
            if (request.version == "HTTP/1.1") {
                return true;
            }
            return false;
        }

        void processRequest(std::string_view requestStr)
        {
            auto request = Request::parse(requestStr);
            if (!request) {
                // I hardcode this `Connection: close` here, so we disconnect clients that try to
                // mess with us
                respond("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
                return;
            }
            auto response = handler_(*request);
            if (Config::get().accesLog) {
                // Inspired by this: https://github.com/expressjs/morgan#predefined-formats
                slog::info(remoteAddr_, " \"", request->requestLine, "\" ",
                    static_cast<int>(response.status), " ", response.body.size());
            }
            respond(response.string(request->version), getKeepAlive(*request));
        }

        void respond(std::string response, bool keepAlive)
        {
            // We need to keep the memory that is referenced in the SQE around, because we don't
            // know when the kernel will copy it, so we save it in this member variable, which
            // definitely lives longer than this send takes to complete.
            // I also prefer the member variable compared to moving it into the lambda, because
            // it can be reused for another request in this session.
            responseBuffer_ = std::move(response);
            connection_.send(responseBuffer_.data(), responseBuffer_.size(),
                [this, self = this->shared_from_this(), keepAlive, size = responseBuffer_.size()](
                    std::error_code ec, int sentBytes) {
                    if (ec) {
                        // I think there are no errors, where we want to shutdown.
                        // Note that ec could be an error that can not be returned by ::send,
                        // because with SSL it might do ::recv as part of Connection::send.
                        slog::error("Error in send: ", ec.message());
                        connection_.close();
                        return;
                    }

                    if (sentBytes == 0) {
                        // I don't know when this would happen for TCP.
                        // For SSL this will happen, when the remote peer closed the
                        // connection during a recv that's part of an SSL_write.
                        // In that case we close (since we can't shutdown).
                        connection_.close();
                        return;
                    }

                    if (sentBytes < static_cast<int>(size)) {
                        // This should not happen with blocking sockets.
                        slog::error("Incomplete send: ", sentBytes, "/", size);
                        connection_.close();
                        return;
                    }

                    if (keepAlive) {
                        start();
                    } else {
                        shutdown();
                    }
                });
        }

        // If this only supported TCP, then using close everywhere would be fine.
        // The difference is most important for TLS, where shutdown will call SSL_shutdown.
        void shutdown()
        {
            connection_.shutdown([this, self = this->shared_from_this()](std::error_code) {
                // There is no way to recover, so ignore the error and close either way.
                connection_.close();
            });
        }

        Connection connection_;
        std::function<Response(const Request&)>& handler_;
        std::string remoteAddr_;
        std::string requestBuffer_;
        std::string responseBuffer_;
    };

    void accept()
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
        acceptAddrLen_ = sizeof(acceptAddr_);
        while (!added) {
            added = io_.accept(listenSocket_, &acceptAddr_, &acceptAddrLen_,
                [this](std::error_code ec, int fd) { handleAccept(ec, fd); });
        }
    }

    void handleAccept(std::error_code ec, int fd)
    {
        if (ec) {
            slog::error("Error in accept: ", ec.message());
        } else {
            const auto addr = ::inet_ntoa(acceptAddr_.sin_addr);
            std::make_shared<Session>(io_, fd, handler_, addr)->start();
        }

        accept();
    }

    IoQueue& io_;
    Fd listenSocket_;
    std::function<Response(const Request&)> handler_;
    ::sockaddr_in acceptAddr_;
    ::socklen_t acceptAddrLen_;
};
