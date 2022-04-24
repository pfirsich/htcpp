#pragma once

#include <memory>
#include <string>
#include <vector>

#include "config.hpp"
#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "log.hpp"

Fd createTcpListenSocket(uint16_t listenPort, uint32_t listenAddr = INADDR_ANY, int backlog = 1024);
std::string errnoToString(int err);

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
            std::cerr << "Could not create listen socket: " << errnoToString(errno) << std::endl;
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
        Session(IoQueue& io, int fd, std::function<Response(const Request&)>& handler)
            : connection_(io, fd)
            , handler_(handler)
        {
            rlog::debug("start session");
            requestBuffer_.reserve(Config::get().defaultRequestSize);
        }

        void start()
        {
            // readRequests is not part of the constructor and in this separate method, because
            // shared_from_this must not be called until the shared_ptr constructor has completed.
            // You would get a bad_weak_ptr exception in shared_from_this if you called it from the
            // Session constructor.
            requestBuffer_.clear();
            readRequest();
        }

        ~Session() = default;

        Session(const Session&) = default;
        Session(Session&&) = default;
        Session& operator=(const Session&) = default;
        Session& operator=(Session&&) = default;

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
                        std::cerr << "Error in recv: " << ec.message() << std::endl;
                        shutdown();
                        return;
                    }

                    if (readBytes > 0) {
                        requestBuffer_.resize(requestBuffer_.size() - readAmount + readBytes);
                    }

                    if (readBytes == 0 || static_cast<size_t>(readBytes) < readAmount) {
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
            // Passing a local variable to respond here *barely* works, because we io_uring_enter
            // as part of the connection_.send call in the TCP case, which ends up copying the
            // buffer to kernel space.
            // In the TLS case SSL_write should copy the whole buffer into the BIO if there is
            // enough space (17K), which should be the case most of the time.
            // This will likely break very, very soon, but I want to wait until it does.
            // If (when?) it does, introduce a responseBuffer_ member variable and assign to that
            // instead.
            const auto responseStr = handler_(*request).string(request->version);
            respond(responseStr, getKeepAlive(*request));
        }

        void respond(std::string_view response, bool keepAlive)
        {
            connection_.send(response.data(), response.size(),
                [this, self = this->shared_from_this(), keepAlive, size = response.size()](
                    std::error_code ec, int sent) {
                    if (ec) {
                        std::cerr << "Error in send: " << ec.message() << std::endl;
                    } else if (sent < static_cast<int>(size)) {
                        // When does this happen?
                        std::cerr << "Incomplete send: " << ec.message() << std::endl;
                    }
                    if (ec || sent < static_cast<int>(size) || !keepAlive) {
                        // If something went wrong (error or incomplete) let the client
                        // retry the whole request.
                        shutdown();
                        return;
                    }
                    start();
                });
        }

        void shutdown()
        {
            connection_.shutdown([this, self = this->shared_from_this()](std::error_code) {
                // There is no way to recover, so ignore the error and close either way.
                connection_.close();
            });
        }

        Connection connection_;
        std::function<Response(const Request&)>& handler_;
        std::string requestBuffer_;
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
        while (!added) {
            added = io_.accept(listenSocket_, nullptr,
                [this](std::error_code ec, int fd) { handleAccept(ec, fd); });
        }
    }

    void handleAccept(std::error_code ec, int fd)
    {
        if (ec) {
            std::cerr << "Error in accept: " << ec.message() << std::endl;
            return;
        }

        std::make_shared<Session>(io_, fd, handler_)->start();

        accept();
    }

    IoQueue& io_;
    Fd listenSocket_;
    std::function<Response(const Request&)> handler_;
};
