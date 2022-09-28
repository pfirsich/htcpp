#pragma once

#include <cstring>
#include <future>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "http.hpp"
#include "ioqueue.hpp"
#include "result.hpp"
#include "tcp.hpp"
#include "util.hpp"

#ifdef TLS_SUPPORT_ENABLED
#include "ssl.hpp"
#endif

template <typename Connection>
constexpr uint16_t defaultPort = 0;

template <>
constexpr uint16_t defaultPort<TcpConnection> = 80;

#ifdef TLS_SUPPORT_ENABLED
template <>
constexpr uint16_t defaultPort<SslConnection> = 443;
#endif

template <typename ConnectionFactory>
struct ClientSession : public std::enable_shared_from_this<ClientSession<ConnectionFactory>> {
public:
    static std::shared_ptr<ClientSession> create(IoQueue& io, std::string_view host, uint16_t port)
    {
        auto session = std::shared_ptr<ClientSession>(new ClientSession(io, host, port));
        return session;
    }

    using Connection = typename ConnectionFactory::Connection;
    using Callback = std::function<void(std::error_code, Response&&)>;

    bool request(Method method, std::string_view target, const HeaderMap<>& headers,
        const std::string& requestBody, Callback cb)
    {
        if (callback_) {
            // Request already in progress. Pipelining is not supported.
            return false;
        }
        callback_ = std::move(cb);
        requestBuffer_ = serializeRequest(method, target, headers, requestBody);
        if (!connection_) {
            connect();
        }
        return true;
    }

private:
    static ConnectionFactory& getConnectionFactory()
    {
        static ConnectionFactory factory;
        return factory;
    }

    ClientSession(IoQueue& io, std::string_view host, uint16_t port = 0)
        : io_(io)
        , host_(host)
        , port_(port ? port : defaultPort<Connection>)
    {
        connectAddr_.ss_family = AF_UNSPEC;
    }

    void resolve()
    {
        io_.async<std::vector<::sockaddr_storage>>(
            [this, self = this->shared_from_this()]() {
                struct ::addrinfo hints;
                std::memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

                std::vector<::sockaddr_storage> addrs;
                ::addrinfo* result;
                const auto port = std::to_string(port_);
                const auto res = ::getaddrinfo(host_.c_str(), port.c_str(), &hints, &result);
                if (res != 0) {
                    slog::error("getaddrinfo: ", gai_strerror(res));
                    return addrs;
                }
                for (::addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
                    slog::debug("addr: family = ", ai->ai_family, ", socktype = ", ai->ai_socktype,
                        ", protocol = ", ai->ai_protocol);
                    std::memcpy(&addrs.emplace_back(), ai->ai_addr, ai->ai_addrlen);
                }
                return addrs;
            },
            [this, self = this->shared_from_this()](
                std::error_code ec, std::vector<::sockaddr_storage>&& addrs) {
                if (ec) {
                    slog::error("Error doing async resolve: ", ec.message());
                    callback_(ec, Response());
                    return;
                }
                if (addrs.empty()) {
                    slog::error("Empty address list");
                    callback_(std::make_error_code(std::errc::host_unreachable), Response());
                    return;
                }
                // Just use the first one?
                std::memcpy(&connectAddr_, &addrs[0], sizeof(::sockaddr_storage));
                connect();
            });
    }

    void connect()
    {
        assert(!connection_);
        if (connectAddr_.ss_family == AF_UNSPEC) {
            resolve();
        } else {
            const auto sock = ::socket(connectAddr_.ss_family, SOCK_STREAM, 0);
            if (sock == -1) {
                slog::error("Error creating socket: ", errnoToString(errno));
                callback_(std::make_error_code(static_cast<std::errc>(errno)), Response());
            }
            assert(connectAddr_.ss_family == AF_INET || connectAddr_.ss_family == AF_INET6);
            const auto addrLen = connectAddr_.ss_family == AF_INET ? sizeof(::sockaddr_in)
                                                                   : sizeof(::sockaddr_in6);
            io_.connect(sock, reinterpret_cast<const ::sockaddr*>(&connectAddr_), addrLen,
                [this, self = this->shared_from_this(), sock](std::error_code ec) {
                    if (ec) {
                        slog::error("Error connecting: ", ec.message());
                        callback_(ec, Response());
                    }
                    connection_ = getConnectionFactory().create(io_, sock);
                    if constexpr (std::is_same_v<Connection, SslConnection>) {
                        connection_->setHostname(host_);
                    }
                    send();
                });
        }
    }

    void send()
    {
        assert(sendCursor_ < requestBuffer_.size());
        connection_->send(requestBuffer_.data() + sendCursor_, requestBuffer_.size() - sendCursor_,
            [this, self = this->shared_from_this()](std::error_code ec, int sentBytes) {
                if (ec) {
                    slog::error("Error sending request: ", ec.message());
                    callback_(ec, Response());
                    connection_->close();
                    return;
                }

                if (sentBytes == 0) {
                    slog::error("0 bytes sent");
                    callback_(std::make_error_code(std::errc::no_message_available), Response());
                    connection_->close();
                    return;
                }

                assert(sentBytes > 0);
                if (sendCursor_ + sentBytes < requestBuffer_.size()) {
                    sendCursor_ += sentBytes;
                    send();
                    return;
                }

                recvHeader();
            });
    }

    void recvHeader()
    {
        const auto recvLen = 1024;
        recvBuffer_.resize(recvLen, '\0');
        connection_->recv(recvBuffer_.data(), recvLen,
            [this, self = this->shared_from_this(), recvLen](std::error_code ec, int readBytes) {
                if (ec) {
                    slog::error("Error in recv (headers): ", ec.message());
                    callback_(ec, Response());
                    connection_->close();
                    return;
                }

                if (readBytes == 0) {
                    slog::error("Connection closed");
                    callback_(std::make_error_code(std::errc::host_unreachable), Response());
                    connection_->close();
                    return;
                }

                recvBuffer_.resize(recvBuffer_.size() - recvLen + readBytes);

                auto response = Response::parse(recvBuffer_);
                if (!response) {
                    slog::error("Could not parse response");
                    callback_(std::make_error_code(std::errc::invalid_argument), Response());
                    connection_->close();
                    return;
                }
                response_ = std::move(*response);

                const auto contentLength = response_.headers.get("Content-Length");
                if (contentLength) {
                    const auto length = parseInt<uint64_t>(*contentLength);
                    if (!length) {
                        slog::error("Invalid Content-Length");
                        callback_(std::make_error_code(std::errc::invalid_argument), Response());
                        connection_->close();
                        return;
                    }

                    if (response_.body.size() < *length) {
                        recvBody(*length);
                    } else {
                        response_.body = response_.body.substr(0, *length);
                        processResponse();
                    }
                } else {
                    processResponse();
                }
            });
    }

    void recvBody(size_t contentLength)
    {
        const auto sizeBeforeRead = response_.body.size();
        assert(sizeBeforeRead < contentLength);
        const auto recvLen = contentLength - sizeBeforeRead;
        response_.body.append(recvLen, '\0');
        const auto buffer = response_.body.data() + sizeBeforeRead;
        connection_->recv(buffer, recvLen,
            [this, self = this->shared_from_this(), recvLen, contentLength](
                std::error_code ec, int readBytes) {
                if (ec) {
                    slog::error("Error in recv (body): ", ec.message());
                    callback_(ec, Response());
                    connection_->close();
                    return;
                }

                if (readBytes == 0) {
                    slog::error("Connection closed");
                    callback_(std::make_error_code(std::errc::host_unreachable), Response());
                    connection_->close();
                    return;
                }

                response_.body.resize(response_.body.size() - recvLen + readBytes);

                if (response_.body.size() < contentLength) {
                    recvBody(contentLength);
                } else {
                    assert(response_.body.size() == contentLength);
                    processResponse();
                }
            });
    }

    void processResponse()
    {
        callback_(std::error_code(), std::move(response_));
        callback_ = nullptr;
        connection_->close();
    }

    std::string serializeRequest(
        Method method, std::string_view target, const HeaderMap<>& headers, std::string_view body)
    {
        std::string req;
        req.reserve(512);
        req.append(toString(method));
        req.append(" ");
        req.append(target);
        req.append(" HTTP/1.1\r\n");
        if (!headers.contains("Host")) {
            req.append("Host: ");
            req.append(host_);
            if (port_ != defaultPort<Connection>) {
                req.append(":");
                req.append(std::to_string(port_));
            }
            req.append("\r\n");
        }
        headers.serialize(req);
        if (body.size() && !headers.contains("Content-Length")) {
            req.append("Content-Length: " + std::to_string(body.size()) + "\r\n");
        }
        req.append("\r\n");
        req.append(body);
        return req;
    }

    IoQueue& io_;
    std::string host_;
    uint16_t port_ = 0;
    sockaddr_storage connectAddr_;
    Callback callback_ = nullptr;
    std::string requestBuffer_;
    Response response_;
    std::string recvBuffer_;
    size_t sendCursor_ = 0;
    std::unique_ptr<Connection> connection_;
};

// This must be called from the main thread! You can tell by the IoQueue& parameter
void request(IoQueue& io, Method method, const std::string_view urlStr, const HeaderMap<>& headers,
    const std::string& requestBody, std::function<void(std::error_code, Response&&)> cb);

class ThreadRequester {
public:
    using RequestResult = Result<Response>;

    // This must be constructed from the main thread
    ThreadRequester(IoQueue& io);

    // This can be called from any thread
    std::future<RequestResult> request(
        Method method, std::string url, HeaderMap<> headers = {}, std::string body = {});

private:
    struct Event {
        std::shared_ptr<std::promise<RequestResult>> promise;
        Method method;
        std::string url;
        HeaderMap<> headers;
        std::string body;
    };

    void eventHandler(Event&& event);

    IoQueue& io_;
    EventListener<Event> eventListener_;
};
