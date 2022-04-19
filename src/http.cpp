#include "http.hpp"

#include "config.hpp"

std::optional<Method> parseMethod(std::string_view method)
{
    if (method == "GET") {
        return Method::Get;
    }
    return std::nullopt;
}

std::optional<Request> Request::parse(std::string_view requestStr)
{
    // e.g.: GET /foobar/barbar http/1.1\r\nHost: example.org\r\n\r\n
    Request req;
    size_t cursor = 0;
    const auto methodDelim = requestStr.substr(cursor, 8).find(' ');
    if (methodDelim == std::string::npos) {
        return std::nullopt;
    }
    const auto methodStr = requestStr.substr(cursor, methodDelim);
    const auto method = parseMethod(methodStr);
    if (!method) {
        return std::nullopt;
    }
    req.method = *method;
    cursor += methodDelim + 1;

    const auto urlLen = requestStr.substr(cursor, Config::get().maxUrlLength).find(' ');
    if (urlLen == std::string::npos) {
        return std::nullopt;
    }
    req.url.full = requestStr.substr(cursor, urlLen);
    const auto queryStart = req.url.full.find('?');
    req.url.path = req.url.full.substr(0, queryStart);
    if (queryStart != std::string_view::npos) {
        const auto fragmentStart = req.url.full.find('#');
        req.url.query = req.url.full.substr(queryStart, fragmentStart - queryStart);
        if (fragmentStart != std::string_view::npos) {
            req.url.fragment = req.url.full.substr(fragmentStart);
        }
    }

    size_t lineStart = requestStr.find("\r\n");
    if (lineStart == std::string_view::npos) {
        return std::nullopt;
    }
    lineStart += 2;

    while (lineStart < requestStr.size()) {
        const auto lineEnd = requestStr.find("\r\n", lineStart);
        if (lineEnd == std::string_view::npos) {
            return std::nullopt;
        }
        if (lineStart == lineEnd) {
            // skip newlines and end header parsing
            lineStart += 2;
            break;
        } else {
            const auto line = requestStr.substr(lineStart, lineEnd - lineStart);
            auto colon = line.find(':');
            if (colon == std::string_view::npos) {
                return std::nullopt;
            }
            const auto name = line.substr(0, colon);
            auto valueStart = colon + 1;
            while (valueStart < line.size() && isHttpWhitespace(line[valueStart])) {
                valueStart++;
            }
            auto valueEnd = valueStart;
            while (valueEnd < line.size() && !isHttpWhitespace(line[valueEnd])) {
                valueEnd++;
            }
            const auto value = line.substr(valueStart, valueEnd - valueStart);
            req.headers.add(name, value);
            lineStart = lineEnd + 2;
        }
    }

    return req;
}

Response::Response(std::string body)
    : body(std::move(body))
{
}

Response::Response(StatusCode code, std::string body)
    : code(code)
    , body(std::move(body))
{
}

std::string Response::string() const
{
    std::string s;
    auto size = 12 + 2; // status line
    const auto headerEntries = headers.getEntries();
    for (const auto& [name, value] : headerEntries) {
        size += name.size() + value.size() + 4;
    }
    size += 2;
    size += body.size();
    s.append("HTTP/1.1 ");
    s.append(std::to_string(static_cast<int>(code)));
    s.append("\r\n");
    for (const auto& [name, value] : headerEntries) {
        s.append(name);
        s.append(": ");
        s.append(value);
        s.append("\r\n");
    }
    s.append("\r\n");
    s.append(body);
    return s;
}
