#pragma once

#include <memory>
#include <string>
#include <vector>

#include "config.hpp"
#include "fd.hpp"
#include "http.hpp"
#include "ioqueue.hpp"
#include "log.hpp"
#include "metrics.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

Fd createTcpListenSocket(uint16_t listenPort, uint32_t listenAddr = INADDR_ANY, int backlog = 1024);

class TcpConnection {
public:
    TcpConnection(IoQueue& io, int fd);

    void recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void recv(void* buffer, size_t len, IoQueue::Timespec* timeout, bool timeoutIsAbsolute,
        IoQueue::HandlerEcRes handler);
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
            , trackInProgressHandle_(Metrics::get().connActive.labels().trackInProgress())
        {
            requestHeaderBuffer_.reserve(Config::get().maxRequestHeaderSize);
            requestBodyBuffer_.reserve(Config::get().maxRequestBodySize);
        }

        ~Session() = default;

        Session(const Session&) = default;
        Session(Session&&) = default;
        Session& operator=(const Session&) = default;
        Session& operator=(Session&&) = default;

        void start()
        {
            // readRequest is not part of the constructor and in this separate method,
            // because shared_from_this must not be called until the shared_ptr constructor has
            // completed. You would get a bad_weak_ptr exception in shared_from_this if you called
            // it from the Session constructor.
            requestStart_ = cpprom::now();
            readRequest();
        }

    private:
        // Inspired by this: https://github.com/expressjs/morgan#predefined-formats
        void accessLog(std::string_view requestLine, StatusCode responseStatus,
            size_t responseContentLength) const
        {
            if (Config::get().accesLog) {
                slog::info(remoteAddr_, " \"", requestLine, "\" ", static_cast<int>(responseStatus),
                    " ", responseContentLength);
            }
        }

        void readRequest()
        {
            requestHeaderBuffer_.clear();
            requestBodyBuffer_.clear();
            IoQueue::setAbsoluteTimeout(&readTimeout_, Config::get().fullReadTimeoutMs);

            const auto recvLen = Config::get().maxRequestHeaderSize;
            requestHeaderBuffer_.append(recvLen, '\0');
            connection_.recv(requestHeaderBuffer_.data(), recvLen,
                // `this->` before `shared_from_this` is necessary or you get an error
                // because of a dependent type lookup.
                [this, self = this->shared_from_this(), recvLen](
                    std::error_code ec, int readBytes) {
                    if (ec) {
                        Metrics::get().recvErrors.labels(ec.message()).inc();
                        slog::error("Error in recv (headers): ", ec.message());
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

                    requestHeaderBuffer_.resize(requestHeaderBuffer_.size() - recvLen + readBytes);

                    auto request = Request::parse(requestHeaderBuffer_);
                    if (!request) {
                        accessLog("INVALID REQUEST", StatusCode::BadRequest, 0);
                        Metrics::get().reqErrors.labels("parse error").inc();
                        respond("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
                        return;
                    }
                    request_ = std::move(*request);

                    const auto contentLength = request_.headers.get("Content-Length");
                    if (contentLength) {
                        const auto length = parseInt<uint64_t>(*contentLength);
                        if (!length) {
                            accessLog(
                                "INVALID REQUEST (Content-Length)", StatusCode::BadRequest, 0);
                            Metrics::get().reqErrors.labels("invalid length").inc();
                            respond("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
                            return;
                        }

                        if (*length > Config::get().maxRequestBodySize) {
                            accessLog("INVALID REQUEST (body size)", StatusCode::BadRequest, 0);
                            Metrics::get().reqErrors.labels("body too large").inc();
                            respond("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
                        } else if (request_.body.size() < *length) {
                            requestBodyBuffer_.append(request_.body);
                            request_.body = std::string_view();
                            readRequestBody(*length);
                        } else {
                            request_.body = request_.body.substr(0, *length);
                            processRequest(request_);
                        }
                    } else {
                        processRequest(request_);
                    }
                });
        }

        void readRequestBody(size_t contentLength)
        {
            const auto sizeBeforeRead = requestBodyBuffer_.size();
            assert(sizeBeforeRead < contentLength);
            const auto recvLen = contentLength - sizeBeforeRead;
            requestBodyBuffer_.append(recvLen, '\0');
            auto buffer = requestBodyBuffer_.data() + sizeBeforeRead;
            connection_.recv(buffer, recvLen,
                [this, self = this->shared_from_this(), recvLen, contentLength](
                    std::error_code ec, int readBytes) {
                    if (ec) {
                        Metrics::get().recvErrors.labels(ec.message()).inc();
                        slog::error("Error in recv (body): ", ec.message());
                        connection_.close();
                        return;
                    }

                    if (readBytes == 0) {
                        connection_.close();
                        return;
                    }

                    requestBodyBuffer_.resize(requestBodyBuffer_.size() - recvLen + readBytes);

                    if (requestBodyBuffer_.size() < contentLength) {
                        readRequestBody(contentLength);
                    } else {
                        assert(requestBodyBuffer_.size() == contentLength);
                        request_.body = std::string_view(requestBodyBuffer_);
                        processRequest(request_);
                    }
                });
        }

        bool getKeepAlive(const Request& request) const
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

        void processRequest(const Request& request)
        {
            Metrics::get().reqsTotal.labels(toString(request.method), request.url.path).inc();
            Metrics::get()
                .reqHeaderSize.labels(toString(request.method), request.url.path)
                .observe(requestHeaderBuffer_.size());
            Metrics::get()
                .reqBodySize.labels(toString(request.method), request.url.path)
                .observe(requestBodyBuffer_.size());
            response_ = handler_(request);
            accessLog(request.requestLine, response_.status, response_.body.size());
            respond(response_.string(request.version), getKeepAlive(request));
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
                    const auto method = toString(request_.method);
                    const auto status = std::to_string(static_cast<int>(response_.status));
                    Metrics::get()
                        .reqDuration.labels(method, request_.url.path)
                        .observe(cpprom::now() - requestStart_);
                    Metrics::get().respTotal.labels(method, request_.url.path, status).inc();
                    Metrics::get().respSize.labels(method, request_.url.path, status).observe(size);

                    if (ec) {
                        // I think there are no errors, where we want to shutdown.
                        // Note that ec could be an error that can not be returned by ::send,
                        // because with SSL it might do ::recv as part of Connection::send.
                        Metrics::get().sendErrors.labels(ec.message()).inc();
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
        // The Request object is the result of request header parsing and consists of many
        // string_views referencing the buffer that the request was parsed from. If that buffer
        // would have to be resized (because of a large body not yet fully received), these
        // references would be invalidated. Hence the body is saved in a separate buffer.
        std::string requestHeaderBuffer_;
        std::string requestBodyBuffer_;
        std::string responseBuffer_;
        Request request_;
        Response response_;
        IoQueue::Timespec readTimeout_;
        cpprom::Gauge::TrackInProgressHandle trackInProgressHandle_;
        double requestStart_;
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
            Metrics::get().acceptErrors.labels(ec.message()).inc();
        } else {
            static auto& connAccepted = Metrics::get().connAccepted.labels();
            connAccepted.inc();
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
