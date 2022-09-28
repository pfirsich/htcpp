#pragma once

#include <cassert>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "string.hpp"

enum class Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
};

std::optional<Method> parseMethod(std::string_view method);
std::string toString(Method method);

enum class StatusCode : uint32_t {
    Invalid = 0,

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

template <typename StringType = std::string>
class HeaderMap {
public:
    HeaderMap() = default;
    HeaderMap(std::vector<std::pair<StringType, StringType>> h);

    bool contains(std::string_view name) const;
    std::optional<std::string_view> get(std::string_view name) const;
    std::vector<std::string_view> getAll(std::string_view name) const;
    std::optional<std::string_view> operator[](std::string_view name) const; // get
    const std::vector<std::pair<StringType, StringType>>& getEntries() const;

    void add(std::string_view name, std::string_view value);
    size_t set(std::string_view name, std::string_view value);
    size_t remove(std::string_view name);

    bool parse(std::string_view str);
    void serialize(std::string& str) const;

private:
    std::optional<size_t> find(std::string_view name) const;

    std::vector<std::pair<StringType, StringType>> headers_;
};

extern template class HeaderMap<std::string_view>;
extern template class HeaderMap<std::string>;

struct Url {
    std::string fullRaw;
    // Most of these are view referencing 'fullRaw'.
    std::string_view scheme;
    std::string_view netLoc;
    std::string_view host; // this is a substring of netLoc
    uint16_t port = 0;
    // This is not a view because of the removal of dot segments.
    std::string_view targetRaw;
    std::string path;
    std::string_view params;
    std::string_view query;
    std::string_view fragment; // This is not technically considered part of the URL (RFC1808)

    static std::optional<Url> parse(std::string_view urlStr);
};

struct Request {
    std::string_view requestLine; // for access log
    Method method;
    Url url;
    std::string_view version;
    HeaderMap<std::string_view> headers;
    std::string_view body;

    std::unordered_map<std::string_view, std::string_view> params;

    static std::optional<Request> parse(std::string_view requestStr);
};

struct Response {
    StatusCode status = StatusCode::Ok;
    HeaderMap<std::string> headers;
    std::string body = {};

    Response();

    Response(std::string body);

    Response(std::string body, std::string_view contentType);

    Response(StatusCode status);

    Response(StatusCode status, std::string body);

    Response(StatusCode status, std::string body, std::string_view contentType);

    void addServerHeader();

    std::string string(std::string_view httpVersion = "HTTP/1.1") const;

    static std::optional<Response> parse(std::string_view responseStr);
};
