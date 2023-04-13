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

Fd createTcpListenSocket(uint16_t listenPort, uint32_t listenAddr, int backlog);

struct Responder {
    virtual ~Responder() = default;
    virtual void respond(Response&& response) = 0;
};

// I don't like this interface, but I feel like it's the most obvious. The "Responder"
// has to have some kind of type erasure (hence the virtual function), because eventually we need to
// call into a TCP and a SSL Session, which are different types (different template instantiations).
// And because we use a virtual function to respond, we need to use some kind of reference-type.
using RequestHandler = std::function<void(const Request&, std::unique_ptr<Responder>)>;

// Maybe I should put the function definitions into server.cpp and instantiate the template
// explicitly for TcpConnection and SslConnection, but I would have include ssl.hpp here, which I do
// not like right now.
template <typename ConnectionFactory>
class Server {
public:
    using Connection = typename ConnectionFactory::Connection;

    Server(IoQueue& io, ConnectionFactory factory, RequestHandler handler,
        Config::Server config = Config::Server {})
        : io_(io)
        , listenSocket_(
              createTcpListenSocket(config.listenPort, config.listenAddress, config.listenBacklog))
        , handler_(std::move(handler))
        , connectionFactory_(std::move(factory))
        , config_(std::move(config))
    {
        if (listenSocket_ == -1) {
            slog::fatal("Could not create listen socket: ", errnoToString(errno));
            std::exit(1);
        }
    };

    void start()
    {
        slog::info("Listening on ", ::inet_ntoa(::in_addr { config_.listenAddress }), ":",
            config_.listenPort);
        accept();
    }

private:
    class Session;

    struct SessionResponder : public Responder {
        // ownership of the session to keep it alive as long as this lives
        std::unique_ptr<Session> session;

        SessionResponder(std::unique_ptr<Session> session)
            : session(std::move(session))
        {
        }

        void respond(Response&& response) override
        {
            assert(session);
            session->respond(std::move(session), std::move(response));
        }
    };

    // A Session will have ownership of itself, but pass it into io queue handlers also.
    class Session {
    public:
        Session(Server& server, std::unique_ptr<Connection> connection, in_addr remoteAddr)
            : server_(server)
            , connection_(std::move(connection))
            , remoteAddr_(remoteAddr.s_addr)
            , remoteAddrStr_(::inet_ntoa(remoteAddr))
            , trackInProgressHandle_(Metrics::get().connActive.labels().trackInProgress())
        {
            requestHeaderBuffer_.reserve(server_.config_.maxRequestHeaderSize);
            requestBodyBuffer_.reserve(server_.config_.maxRequestBodySize);
            server_.numConnections_++;
        }

        ~Session() { server_.numConnections_--; }

        Session(const Session&) = default;
        Session(Session&&) = default;
        Session& operator=(const Session&) = default;
        Session& operator=(Session&&) = default;

        void start(std::unique_ptr<Session> self)
        {
            requestStart_ = cpprom::now();
            readRequest(std::move(self));
        }

    private:
        friend class SessionResponder;

        // Inspired by this: https://github.com/expressjs/morgan#predefined-formats
        void accessLog(std::string_view requestLine, StatusCode responseStatus,
            size_t responseContentLength) const
        {
            if (server_.config_.accesLog) {
                slog::info(remoteAddrStr_, " \"", requestLine, "\" ",
                    static_cast<int>(responseStatus), " ", responseContentLength);
            }
        }

        void readRequest(std::unique_ptr<Session> self)
        {
            requestHeaderBuffer_.clear();
            requestBodyBuffer_.clear();
            IoQueue::setAbsoluteTimeout(&recvTimeout_, server_.config_.fullReadTimeoutMs);

            const auto recvLen = server_.config_.maxRequestHeaderSize;
            requestHeaderBuffer_.append(recvLen, '\0');
            connection_->recv(requestHeaderBuffer_.data(), recvLen, &recvTimeout_,
                [this, self = std::move(self), recvLen](std::error_code ec, int readBytes) mutable {
                    if (ec) {
                        Metrics::get().recvErrors.labels(ec.message()).inc();
                        slog::error("Error in recv (headers): ", ec.message());
                        // Error might be ECONNRESET, EPIPE (from send) or others, where we just
                        // want to close. There might be errors, where shutdown is better, but
                        // especially with SSL almost all errors here require us to NOT shutdown.
                        // Same applies for send below.
                        // A notable exception is ECANCELED caused by an expiration of the read
                        // timeout.
                        if (ec.value() == ECANCELED) {
                            shutdown(std::move(self));
                        } else {
                            connection_->close();
                        }
                        return;
                    }

                    if (readBytes == 0) {
                        connection_->close();
                        return;
                    }

                    requestHeaderBuffer_.resize(requestHeaderBuffer_.size() - recvLen + readBytes);

                    auto request = Request::parse(requestHeaderBuffer_);
                    if (!request) {
                        accessLog("INVALID REQUEST", StatusCode::BadRequest, 0);
                        Metrics::get().reqErrors.labels("parse error").inc();
                        respond(std::move(self),
                            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
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
                            respond(std::move(self),
                                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
                            return;
                        }

                        if (*length > server_.config_.maxRequestBodySize) {
                            accessLog("INVALID REQUEST (body size)", StatusCode::BadRequest, 0);
                            Metrics::get().reqErrors.labels("body too large").inc();
                            respond(std::move(self),
                                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false);
                        } else if (request_.body.size() < *length) {
                            requestBodyBuffer_.append(request_.body);
                            request_.body = std::string_view();
                            readRequestBody(std::move(self), *length);
                        } else {
                            request_.body = request_.body.substr(0, *length);
                            processRequest(std::move(self), request_);
                        }
                    } else {
                        processRequest(std::move(self), request_);
                    }
                });
        }

        void readRequestBody(std::unique_ptr<Session> self, size_t contentLength)
        {
            const auto sizeBeforeRead = requestBodyBuffer_.size();
            assert(sizeBeforeRead < contentLength);
            const auto recvLen = contentLength - sizeBeforeRead;
            requestBodyBuffer_.append(recvLen, '\0');
            auto buffer = requestBodyBuffer_.data() + sizeBeforeRead;
            connection_->recv(buffer, recvLen, &recvTimeout_,
                [this, self = std::move(self), recvLen, contentLength](
                    std::error_code ec, int readBytes) mutable {
                    if (ec) {
                        Metrics::get().recvErrors.labels(ec.message()).inc();
                        slog::error("Error in recv (body): ", ec.message());
                        connection_->close();
                        return;
                    }

                    if (readBytes == 0) {
                        connection_->close();
                        return;
                    }

                    requestBodyBuffer_.resize(requestBodyBuffer_.size() - recvLen + readBytes);

                    if (requestBodyBuffer_.size() < contentLength) {
                        readRequestBody(std::move(self), contentLength);
                    } else {
                        assert(requestBodyBuffer_.size() == contentLength);
                        request_.body = std::string_view(requestBodyBuffer_);
                        processRequest(std::move(self), request_);
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

        void processRequest(std::unique_ptr<Session> self, const Request& request)
        {
            Metrics::get()
                .reqHeaderSize.labels(toString(request.method), request.url.path)
                .observe(requestHeaderBuffer_.size());
            Metrics::get()
                .reqBodySize.labels(toString(request.method), request.url.path)
                .observe(requestBodyBuffer_.size());
            server_.handler_(request, std::make_unique<SessionResponder>(std::move(self)));
        }

        void respond(std::unique_ptr<Session> self, Response&& response)
        {
            response_ = std::move(response);
            const auto status = std::to_string(static_cast<int>(response_.status));
            Metrics::get()
                .reqsTotal.labels(toString(request_.method), request_.url.path, status)
                .inc();
            accessLog(request_.requestLine, response_.status, response_.body.size());
            respond(std::move(self), response_.string(request_.version), getKeepAlive(request_));
        }

        void respond(std::unique_ptr<Session> self, std::string response, bool keepAlive)
        {
            // We need to keep the memory that is referenced in the SQE around, because we don't
            // know when the kernel will copy it, so we save it in this member variable, which
            // definitely lives longer than this send takes to complete.
            // I also prefer the member variable compared to moving it into the lambda, because
            // it can be reused for another request in this session.
            responseBuffer_ = std::move(response);
            responseSendOffset_ = 0;
            keepAlive_ = keepAlive;
            sendResponse(std::move(self));
        }

        void sendResponse(std::unique_ptr<Session> self)
        {
            assert(responseSendOffset_ < responseBuffer_.size());
            connection_->send(responseBuffer_.data() + responseSendOffset_,
                responseBuffer_.size() - responseSendOffset_,
                [this, self = std::move(self)](std::error_code ec, int sentBytes) mutable {
                    if (ec) {
                        // I think there are no errors, where we want to shutdown.
                        // Note that ec could be an error that can not be returned by ::send,
                        // because with SSL it might do ::recv as part of Connection::send.
                        Metrics::get().sendErrors.labels(ec.message()).inc();
                        slog::error("Error in send: ", ec.message());
                        connection_->close();
                        return;
                    }

                    if (sentBytes == 0) {
                        // I don't know when this would happen for TCP.
                        // For SSL this will happen, when the remote peer closed the
                        // connection during a recv that's part of an SSL_write.
                        // In that case we close (since we can't shutdown).
                        connection_->close();
                        return;
                    }

                    assert(sentBytes > 0);
                    if (responseSendOffset_ + sentBytes < responseBuffer_.size()) {
                        responseSendOffset_ += sentBytes;
                        sendResponse(std::move(self));
                        return;
                    }

                    // Only step these counters for successful sends
                    const auto method = toString(request_.method);
                    const auto status = std::to_string(static_cast<int>(response_.status));
                    Metrics::get()
                        .reqDuration.labels(method, request_.url.path)
                        .observe(cpprom::now() - requestStart_);
                    Metrics::get().respTotal.labels(method, request_.url.path, status).inc();
                    Metrics::get()
                        .respSize.labels(method, request_.url.path, status)
                        .observe(responseBuffer_.size());

                    if (keepAlive_) {
                        start(std::move(self));
                    } else {
                        shutdown(std::move(self));
                    }
                });
        }

        // If this only supported TCP, then using close everywhere would be fine.
        // The difference is most important for TLS, where shutdown will call SSL_shutdown.
        void shutdown(std::unique_ptr<Session> self)
        {
            connection_->shutdown([this, self = std::move(self)](std::error_code) {
                // There is no way to recover, so ignore the error and close either way.
                connection_->close();
            });
        }

        Server& server_;
        std::unique_ptr<Connection> connection_;
        uint32_t remoteAddr_;
        std::string remoteAddrStr_;
        // The Request object is the result of request header parsing and consists of many
        // string_views referencing the buffer that the request was parsed from. If that buffer
        // would have to be resized (because of a large body not yet fully received), these
        // references would be invalidated. Hence the body is saved in a separate buffer.
        std::string requestHeaderBuffer_;
        std::string requestBodyBuffer_;
        std::string responseBuffer_;
        Request request_;
        Response response_;
        IoQueue::Timespec recvTimeout_;
        cpprom::Gauge::TrackInProgressHandle trackInProgressHandle_;
        double requestStart_;
        size_t responseSendOffset_ = 0;
        bool keepAlive_;
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
            added = io_.accept(
                listenSocket_, &acceptAddr_, &acceptAddrLen_, [this](std::error_code ec, int fd) {
                    handleAccept(ec, fd);
                    accept();
                });
        }
    }

    void handleAccept(std::error_code ec, int fd)
    {
        if (ec) {
            slog::error("Error in accept: ", ec.message());
            Metrics::get().acceptErrors.labels(ec.message()).inc();
            return;
        }

        static auto& connAccepted = Metrics::get().connAccepted.labels();
        connAccepted.inc();

        if (config_.limitConnections && numConnections_ >= *config_.limitConnections) {
            slog::info("Max concurrent connections limit reached");
            io_.close(fd, [](std::error_code) {});
            return;
        }

        auto conn = connectionFactory_.create(io_, fd);
        if (!conn) {
            slog::info("Could not create connection object (connection factory not ready)");
            io_.close(fd, [](std::error_code) {});
            return;
        }

        auto session = std::make_unique<Session>(*this, std::move(conn), acceptAddr_.sin_addr);
        session->start(std::move(session));
    }

    IoQueue& io_;
    Fd listenSocket_;
    RequestHandler handler_;
    ::sockaddr_in acceptAddr_;
    ::socklen_t acceptAddrLen_;
    ConnectionFactory connectionFactory_;
    Config::Server config_;
    size_t numConnections_ = 0;
};
