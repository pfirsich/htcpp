#include <iostream>
#include <memory>
#include <queue>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "fd.hpp"
#include "ioqueue.hpp"

using namespace std::literals;

namespace Http {
enum class Method {
    Get = 1,
    Head = 2,
    Post = 4,
    Put = 8,
    Delete = 16,
    Connect = 32,
    Options = 64,
    Trace = 128,
    Patch = 256,
};

enum class StatusCode {
    // 1xx = Informational Response
    Continue = 100,
    SwitchingProtocols = 101,
    Processing = 102,
    EarlyHints = 103,

    // 2xx = Success
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritativeInformation = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MultiStatus = 207,
    AlreadyReported = 208,
    ImUsed = 209,

    // 3xx = Redirection
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    SwitchProxy = 306,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,

    // 4xx = Client Errors
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    ImATeapot = 418,
    MisdirectedRequest = 421,
    UnprocessableEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    TooEarly = 425,
    UpgradeRequired = 426,
    PreconditionRequired = 428,
    TooManyRequests = 429,
    RequestHeaderFieldsTooLarge = 431,
    UnavailableForLegalReasons = 451,

    // 5xx = Server Errors
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    NotExtended = 510,
    NetworkAuthenticationRequired = 511,
};

struct Request {
    Method method;
    std::string_view url;
    std::unordered_map<std::string_view, std::string_view> headers;
    std::string_view body;
};

struct Response {
    Response() = default;

    Response(std::string body)
        : body(std::move(body))
    {
    }

    Response(StatusCode code, std::string body)
        : code(code)
        , body(std::move(body))
    {
    }

    std::string string() const
    {
        std::string s;
        auto size = 12 + 2; // status line
        for (const auto& [name, value] : headers) {
            size += name.size() + value.size() + 4;
        }
        size += 2;
        size += body.size();
        s.append("HTTP/1.1 ");
        s.append(std::to_string(static_cast<int>(code)));
        s.append("\r\n");
        for (const auto& [name, value] : headers) {
            s.append(name);
            s.append(": ");
            s.append(value);
            s.append("\r\n");
        }
        s.append("\r\n");
        s.append(body);
        return s;
    }

    StatusCode code = StatusCode::Ok;
    std::vector<std::pair<std::string, std::string>> headers = {};
    std::string body = {};
};

class Server {
public:
    Server()
        : listenSocket_(createTcpListenSocket(6969))
    {
        if (listenSocket_ == -1) {
            std::cerr << "Could not create listen socket: "
                      << std::make_error_code(static_cast<std::errc>(errno)).message() << std::endl;
            std::exit(1);
        }
    };

    void start()
    {
        accept();
        io_.run();
    }

    void route(std::string url, Method method, std::function<Response(const Request&)> handler)
    {
        routes_.push_back(Route { url, method, handler });
    }

private:
    struct Route {
        std::string url;
        Method method;
        std::function<Response(const Request&)> handler;

        bool match(const Request& request) const
        {
            return method == request.method && url == request.url;
        }
    };

    // A connection will have ownership of itself and decide on its own when it's time to be
    // destroyed
    class Connection : public std::enable_shared_from_this<Connection> {
    public:
        Connection(IoQueue& io, int fd, const std::vector<Route>& routes)
            : io_(io)
            , fd_(fd)
            , routes_(routes)
        {
            request_.reserve(512);
        }

        ~Connection()
        {
            std::cout << "I died" << std::endl;
        }

        void start()
        {
            std::cout << "start" << std::endl;
            readSome();
        }

        void close()
        {
            std::cout << "close" << std::endl;
            io_.close(fd_, [self = shared_from_this()](std::error_code /*ec*/) {});
        }

    private:
        static constexpr std::string_view badRequest
            = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";

        void respondAndClose(std::string_view response)
        {
            io_.send(fd_, response.data(), response.size(),
                [this, self = shared_from_this()](
                    std::error_code /*ec*/, int /*sent*/) { close(); });
        }

        std::optional<Method> parseMethod(std::string_view method)
        {
            if (method == "GET") {
                return Method::Get;
            }
            return std::nullopt;
        }

        std::optional<Request> parseRequest(std::string_view request)
        {
            // e.g.: GET /foobar/barbar http/1.1\r\nHost: example.org\r\n\r\n
            Request req;
            size_t cursor = 0;
            const auto methodDelim = request.substr(cursor, 8).find(' ');
            if (methodDelim == std::string::npos) {
                return std::nullopt;
            }
            const auto methodStr = request.substr(cursor, methodDelim);
            const auto method = parseMethod(methodStr);
            if (!method) {
                return std::nullopt;
            }
            req.method = *method;
            cursor += methodDelim + 1;

            constexpr size_t maxUrlLength = 2048;
            const auto urlLen = request.substr(cursor, maxUrlLength).find(' ');
            if (urlLen == std::string::npos) {
                return std::nullopt;
            }
            req.url = request.substr(cursor, urlLen);

            return req;
        }

        void processRequest(std::string_view requestStr)
        {
            auto request = parseRequest(requestStr);
            if (!request) {
                respondAndClose(badRequest);
                return;
            }
            for (const auto& route : routes_) {
                if (route.match(*request)) {
                    const auto resp = route.handler(*request);
                    respondAndClose(resp.string());
                    return;
                }
            }
            // No matching route
            respondAndClose("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
        }

        void readSome()
        {
            std::cout << "read" << std::endl;
            constexpr size_t readAmount = 128;
            const auto currentSize = request_.size();
            request_.append(readAmount, '\0');
            auto buf = request_.data() + currentSize;
            io_.recv(fd_, buf, readAmount,
                [this, self = shared_from_this()](std::error_code ec, int readBytes) {
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

        IoQueue& io_;
        int fd_;
        std::string request_;
        const std::vector<Route>& routes_;
    };

    static Fd createTcpListenSocket(
        uint16_t listenPort, uint32_t listenAddr = INADDR_ANY, int backlog = 128)
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

    void accept()
    {
        io_.accept(
            listenSocket_, nullptr, [this](std::error_code ec, int fd) { handleAccept(ec, fd); });
    }

    void handleAccept(std::error_code ec, int fd)
    {
        std::cout << "handle" << std::endl;
        if (ec) {
            std::cerr << "Error: " << ec.message() << std::endl;
            std::exit(1);
        }

        auto conn = std::make_shared<Connection>(io_, fd, routes_);
        conn->start();

        accept();
    }

    IoQueue io_;
    Fd listenSocket_;
    std::vector<Route> routes_;
};
}

int main()
{
    Http::Server http;
    http.route(
        "/", Http::Method::Get, [](const Http::Request&) -> Http::Response { return "Hi!"s; });
    http.route("/foo", Http::Method::Get,
        [](const Http::Request&) -> Http::Response { return "This is foo"s; });
    http.start();
}
