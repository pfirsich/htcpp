#include "http.hpp"

#include <cassert>

#include "config.hpp"
#include "log.hpp"

std::optional<Method> parseMethod(std::string_view method)
{
    // RFC2616, 5.1.1: "The method is case-sensitive"
    if (method == "GET") {
        return Method::Get;
    } else if (method == "HEAD") {
        return Method::Head;
    } else if (method == "POST") {
        return Method::Post;
    } else if (method == "PUT") {
        return Method::Put;
    } else if (method == "DELETE") {
        return Method::Delete;
    } else if (method == "CONNECT") {
        return Method::Connect;
    } else if (method == "OPTIONS") {
        return Method::Options;
    } else if (method == "TRACE") {
        return Method::Trace;
    } else if (method == "PATCH") {
        return Method::Patch;
    }
    return std::nullopt;
}

std::string toString(Method method)
{
    switch (method) {
    case Method::Get:
        return "GET";
    case Method::Head:
        return "HEAD";
    case Method::Post:
        return "POST";
    case Method::Put:
        return "PUT";
    case Method::Delete:
        return "DELETE";
    case Method::Connect:
        return "CONNECT";
    case Method::Options:
        return "OPTIONS";
    case Method::Trace:
        return "TRACE";
    case Method::Patch:
        return "PATCH";
    default:
        return "invalid";
    }
}

template <typename StringType>
HeaderMap<StringType>::HeaderMap(std::vector<std::pair<StringType, StringType>> h)
    : headers_(std::move(h))
{
}

template <typename StringType>
bool HeaderMap<StringType>::contains(std::string_view name) const
{
    return find(name).has_value();
}

template <typename StringType>
std::optional<std::string_view> HeaderMap<StringType>::get(std::string_view name) const
{
    const auto idx = find(name);
    if (idx) {
        return headers_[*idx].second;
    } else {
        return std::nullopt;
    }
}

template <typename StringType>
std::vector<std::string_view> HeaderMap<StringType>::getAll(std::string_view name) const
{
    std::vector<std::string_view> values;
    for (const auto& [k, v] : headers_) {
        if (ciEqual(k, name)) {
            values.push_back(v);
        }
    }
    return values;
}

template <typename StringType>
void HeaderMap<StringType>::add(std::string_view name, std::string_view value)
{
    headers_.emplace_back(StringType(name), StringType(value));
}

template <typename StringType>
size_t HeaderMap<StringType>::set(std::string_view name, std::string_view value)
{
    const auto removed = remove(name);
    add(name, value);
    return removed;
}

template <typename StringType>
size_t HeaderMap<StringType>::remove(std::string_view name)
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

template <typename StringType>
std::optional<std::string_view> HeaderMap<StringType>::operator[](std::string_view name) const
{
    return get(name);
}

template <typename StringType>
const std::vector<std::pair<StringType, StringType>>& HeaderMap<StringType>::getEntries() const
{
    return headers_;
}

template <typename StringType>
void HeaderMap<StringType>::serialize(std::string& str) const
{
    for (const auto& [name, value] : headers_) {
        str.append(name);
        str.append(": ");
        str.append(value);
        str.append("\r\n");
    }
}

template <typename StringType>
bool HeaderMap<StringType>::parse(std::string_view str)
{
    size_t cursor = 0;
    while (cursor < str.size()) {
        const auto headerLineEnd = str.find("\r\n", cursor);
        const auto line = str.substr(cursor,
            headerLineEnd == std::string_view::npos ? headerLineEnd : headerLineEnd - cursor);
        auto colon = line.find(':');
        if (colon == std::string_view::npos) {
            slog::debug("No colon in header line");
            return false;
        }
        const auto name = line.substr(0, colon);
        const auto value = httpTrim(line.substr(colon + 1));
        add(name, value);
        if (headerLineEnd == std::string_view::npos) {
            break;
        }
        cursor = headerLineEnd + 2;
    }
    return true;
}

template <typename StringType>
std::optional<size_t> HeaderMap<StringType>::find(std::string_view name) const
{
    for (size_t i = 0; i < headers_.size(); ++i) {
        if (ciEqual(headers_[i].first, name)) {
            return i;
        }
    }
    return std::nullopt;
}

template class HeaderMap<std::string_view>;
template class HeaderMap<std::string>;

namespace {
std::string removeDotSegments(std::string_view input)
{
    // RFC3986, 5.2.4: Remove Dot Segments
    // This algorithm is a bit different, because of the following assert (ensured in Url::parse).
    // If we leave the trailing slashes in the input buffer, we know that after every step in the
    // loop below, inputLeft still starts with a slash.
    assert(!input.empty() && input[0] == '/');
    std::string output;
    output.reserve(input.size());
    while (!input.empty()) {
        assert(input[0] == '/');

        if (input == "/") {
            output.push_back('/');
            break;
        } else {
            // I think it's not very clear, why this works in all cases, but if I go through all
            // cases one by one instead, it's just a bunch of ifs with the same code in each branch.
            const auto segmentLength = input.find('/', 1);
            const auto segment = input.substr(0, segmentLength);

            if (segment == "/.") {
                // do nothing
            } else if (segment == "/..") {
                // Removing trailing segment (including slash) from output buffer
                const auto lastSlash = output.rfind('/');
                if (lastSlash != std::string::npos) {
                    output.resize(lastSlash);
                } else {
                    // Considering that every segment starts with a slash, output must be empty
                    assert(output.empty());
                }
            } else {
                output.append(segment);
            }

            if (segmentLength == std::string_view::npos) {
                break;
            } else {
                input = input.substr(segmentLength);
            }
        }
    }
    if (output.empty()) {
        output.push_back('/');
    }
    return output;
}

bool isAlphaNum(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch >= 'A' || ch <= 'Z');
}

bool isSchemeChar(char ch)
{
    return isAlphaNum(ch) || ch == '+' || ch == '.' || ch == '-';
}
}

std::optional<Url> Url::parse(std::string_view urlStr)
{
    constexpr auto npos = std::string_view::npos;

    Url url;
    url.fullRaw = urlStr;
    urlStr = std::string_view(url.fullRaw);

    // There was a case for urlStr == "*" before, but it was referencing a section in an RFC does
    // not exist. I'll leave this comment in case a more knowledgable me in the future knows what
    // this was about.

    // I don't *actually* support CONNECT, so I will not parse authority URIs.

    // RFC1808, 2.4.1: The fragment is not technically part of the URL
    const auto fragmentStart = urlStr.find('#');
    if (fragmentStart != npos) {
        url.fragment = urlStr.substr(fragmentStart + 1);
        urlStr = urlStr.substr(0, fragmentStart);
    }

    if (urlStr.empty()) {
        return std::nullopt;
    }

    // The other possible URLs are absoluteURI and abs_path and I have to parse absoluteURI:
    // "To allow for transition to absoluteURIs in all requests in future
    // versions of HTTP, all HTTP / 1.1 servers MUST accept the absoluteURI form in requests, even
    // though HTTP/1.1 clients will only generate them in requests to proxies."
    // I won't save any of the URI components that are part of absoluteURI (and not abs_path)
    // because I don't need them (even though I should).
    const auto colon = urlStr.find(':');
    if (colon != npos) {
        // RFC1808, 2.4.2: If all characters up to this colon are valid characters for a scheme,
        // [0, colon) is a scheme.
        bool isScheme = true;
        for (size_t i = 0; i < colon; ++i) {
            if (!isSchemeChar(urlStr[i])) {
                isScheme = false;
                break;
            }
        }

        if (isScheme) {
            url.scheme = urlStr.substr(0, colon);
            // If we wanted to save the scheme
            urlStr = urlStr.substr(colon + 1);
        }
    }

    // RFC1808, 2.4.3
    if (urlStr.size() >= 2 && urlStr.substr(0, 2) == "//") {
        // I MUST (RFC2616, 5.2) with 400 if net_loc does not contain a valid host for this server,
        // but I don't want to add configuration for this, so I choose to be more "lenient" here and
        // ignore it completely. choose to be more "lenient" here and simply ignore it completely.
        const auto pathStart = urlStr.find("/", 2);
        if (pathStart == npos) {
            return std::nullopt;
        }
        url.netLoc = urlStr.substr(2, pathStart - 2);
        const auto at = url.netLoc.find('@');
        const auto hostPortStart = at == npos ? 0 : at + 1;
        const auto hostPort = url.netLoc.substr(hostPortStart);
        const auto portDelim = hostPort.find(':');
        url.host = hostPort.substr(0, portDelim);
        if (portDelim != npos) {
            const auto port = parseInt<uint16_t>(hostPort.substr(portDelim + 1));
            if (!port) {
                return std::nullopt;
            }
            url.port = *port;
        }
        urlStr = urlStr.substr(pathStart);
    }
    url.targetRaw = urlStr;

    // RFC1808, 2.4.4
    const auto queryStart = urlStr.find('?');
    if (queryStart != npos) {
        url.query = urlStr.substr(queryStart + 1);
        urlStr = urlStr.substr(0, queryStart);
    }

    // RFC1808, 2.4.5
    const auto paramsStart = urlStr.find(';');
    if (paramsStart != npos) {
        url.params = urlStr.substr(paramsStart + 1);
        urlStr = urlStr.substr(0, paramsStart);
    }

    // If the URI is absoluteURI, we jumped to the slash, otherwise it has to be
    // abs_path, which must start with a slash. (RFC1808, 2.2)
    if (urlStr.empty() || urlStr[0] != '/') {
        return std::nullopt;
    }
    url.path = removeDotSegments(urlStr);

    return url;
}

std::optional<Request> Request::parse(std::string_view requestStr)
{
    // e.g.: GET /foobar/barbar HTTP/1.1\r\nHost: example.org\r\n\r\n
    Request req;

    const auto requestLineEnd = requestStr.find("\r\n");
    if (requestLineEnd == std::string::npos) {
        slog::debug("No request line end");
        return std::nullopt;
    }
    req.requestLine = requestStr.substr(0, requestLineEnd);

    const auto methodDelim = req.requestLine.find(' ');
    if (methodDelim == std::string::npos) {
        slog::debug("No method delimiter");
        return std::nullopt;
    }
    const auto methodStr = req.requestLine.substr(0, methodDelim);
    // We'll allow OPTIONS in HTTP/1.0 too
    const auto method = parseMethod(methodStr);
    if (!method) {
        slog::debug("Invalid method");
        return std::nullopt;
    }
    req.method = *method;

    // I could skip all whitespace here to be more robust, but RFC2616 5.1 only mentions 1 SP
    const auto urlStart = methodDelim + 1;
    if (urlStart >= req.requestLine.size()) {
        slog::debug("No URL");
        return std::nullopt;
    }
    const auto urlLen = req.requestLine.substr(urlStart).find(' ');
    if (urlLen == std::string::npos) {
        slog::debug("No URL end");
        return std::nullopt;
    }
    const auto url = Url::parse(req.requestLine.substr(urlStart, urlLen));
    if (!url) {
        slog::debug("Invalid URL");
        return std::nullopt;
    }
    req.url = url.value();

    const auto versionStart = urlStart + urlLen + 1;
    if (versionStart > req.requestLine.size()) {
        slog::debug("No version start");
        return std::nullopt;
    }
    req.version = req.requestLine.substr(versionStart);

    if (req.version.size() != 8 || req.version.substr(0, 7) != "HTTP/1."
        || (req.version[7] != '0' && req.version[7] != '1')) {
        slog::debug("Invalid version");
        return std::nullopt;
    }

    const auto headersStart = requestLineEnd + 2;
    const auto headersEnd = requestStr.find("\r\n\r\n", headersStart);

    if (headersEnd == std::string_view::npos) {
        slog::debug("No headers end");
        return std::nullopt;
    }

    // +2 to terminate the last header line
    if (!req.headers.parse(requestStr.substr(headersStart, headersEnd + 2 - headersStart))) {
        return std::nullopt;
    }

    req.body = requestStr.substr(headersEnd + 4);

    return req;
}

Response::Response()
    : status(StatusCode::Invalid)
{
}

Response::Response(std::string body)
    : body(std::move(body))
{
    addServerHeader();
}

Response::Response(std::string body, std::string_view contentType)
    : body(std::move(body))
{
    addServerHeader();
    headers.add("Content-Type", contentType);
}

Response::Response(StatusCode status, std::string body)
    : status(status)
    , body(std::move(body))
{
    addServerHeader();
}

Response::Response(StatusCode status)
    : status(status)
{
    addServerHeader();
}

Response::Response(StatusCode status, std::string body, std::string_view contentType)
    : status(status)
    , body(std::move(body))
{
    addServerHeader();
    headers.add("Content-Type", contentType);
}

void Response::addServerHeader()
{
    // I think it's useful to provide this header so clients can work around issues,
    // but I avoid the version, because this might expose too much information (like your server
    // being outdated or your patch cycle). E.g. if the server version bumps only on thursdays, that
    // could be valuable information.
    // If I add a reverse-proxy mode, I must not add this.
    headers.add("Server", "htcpp");
}

std::string Response::string(std::string_view httpVersion) const
{
    std::string s;
    s.reserve(512);
    auto size = 12 + 2; // status line
    const auto headerEntries = headers.getEntries();
    for (const auto& [name, value] : headerEntries) {
        size += name.size() + value.size() + 4;
    }
    size += 2;
    size += body.size();
    s.append(httpVersion);
    s.append(" ");
    s.append(std::to_string(static_cast<int>(status)));
    // The reason phrase may be empty, but the separator space is not optional
    s.append(" \r\n");
    headers.serialize(s);
    if (!headers.contains("Content-Length") && !body.empty()) {
        s.append("Content-Length: ");
        s.append(std::to_string(body.size()));
        s.append("\r\n");
    }
    s.append("\r\n");
    s.append(body);
    return s;
}

std::optional<Response> Response::parse(std::string_view responseStr)
{
    if (responseStr.substr(0, 7) != "HTTP/1.") {
        slog::debug("Response doesn't start with HTTP");
        return std::nullopt;
    }
    const auto statusLineEnd = responseStr.find("\r\n");
    if (!statusLineEnd) {
        slog::debug("No status line end");
        return std::nullopt;
    }
    const auto statusLine = responseStr.substr(0, statusLineEnd);

    const auto statusStart = statusLine.find(' ') + 1;
    const auto statusEnd = statusLine.find_first_of(" \r\n", statusStart);
    const auto statusCodeStr = statusLine.substr(statusStart, statusEnd - statusStart);
    const auto statusCode = parseInt<uint32_t>(statusCodeStr);
    if (!statusCode) {
        slog::debug("Invalid status code: '", statusCodeStr, "'");
        return std::nullopt;
    }

    const auto headersStart = statusLineEnd + 2;
    const auto headersEnd = responseStr.find("\r\n\r\n", headersStart);

    if (headersEnd == std::string_view::npos) {
        slog::debug("No headers end");
        return std::nullopt;
    }

    Response resp;

    resp.status = static_cast<StatusCode>(*statusCode);

    // +2 so the last header line is terminated as well (makes parsing the headers easier)
    if (!resp.headers.parse(responseStr.substr(headersStart, headersEnd + 2 - headersStart))) {
        return std::nullopt;
    }

    resp.body = responseStr.substr(headersEnd + 4);

    return resp;
}
