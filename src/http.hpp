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

template <typename StringType>
class HeaderMap {
public:
    bool contains(std::string_view name) const
    {
        return find(name).has_value();
    }

    std::optional<std::string_view> get(std::string_view name) const
    {
        const auto idx = find(name);
        if (idx) {
            return headers_[*idx].second;
        } else {
            return std::nullopt;
        }
    }

    std::vector<std::string_view> getAll(std::string_view name) const
    {
        std::vector<std::string_view> values;
        for (const auto& [k, v] : headers_) {
            if (ciEqual(k, name)) {
                values.push_back(v);
            }
        }
        return values;
    }

    void add(std::string_view name, std::string_view value)
    {
        headers_.emplace_back(StringType(name), StringType(value));
    }

    size_t set(std::string_view name, std::string_view value)
    {
        const auto removed = remove(name);
        add(name, value);
        return removed;
    }

    size_t remove(std::string_view name)
    {
        size_t removed = 0;
        for (auto it = headers_.begin(); it != headers_.end();) {
            if (ciEqual(it->first, name)) {
                it = headers_.erase(it);
                removed++;
            } else {
                ++it;
            }
        }
        return removed;
    }

    std::optional<std::string_view> operator[](std::string_view name) const
    {
        return get(name);
    }

    const std::vector<std::pair<StringType, StringType>>& getEntries() const
    {
        return headers_;
    }

private:
    std::optional<size_t> find(std::string_view name) const
    {
        for (size_t i = 0; i < headers_.size(); ++i) {
            if (ciEqual(headers_[i].first, name)) {
                return i;
            }
        }
        return std::nullopt;
    }

    std::vector<std::pair<StringType, StringType>> headers_;
};

struct Url {
    std::string_view fullRaw;
    // It would be nice, if these could be string_views, but because of percent decoding and
    // removing dot segments, we have to create copies.
    std::string path;
    std::string params;
    std::string query;
    std::string fragment; // This is not technically considered part of the URL (RFC1808)

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
    Response();

    Response(std::string body);

    Response(std::string body, std::string_view contentType);

    Response(StatusCode status);

    Response(StatusCode status, std::string body);

    Response(StatusCode status, std::string body, std::string_view contentType);

    void addServerHeader();

    std::string string(std::string_view httpVersion) const;

    StatusCode status = StatusCode::Ok;
    HeaderMap<std::string> headers;
    std::string body = {};
};
