#pragma once

#include <functional>

#include "http.hpp"
#include "server.hpp"

class Router {
public:
    using RouteParams = std::unordered_map<std::string_view, std::string_view>;

    void route(std::string_view pattern,
        std::function<void(const Request&, const RouteParams&, std::shared_ptr<Responder>)>
            handler);

    void route(std::string_view pattern,
        std::function<Response(const Request&, const RouteParams&)> handler);

    void route(Method method, std::string_view pattern,
        std::function<void(const Request&, const RouteParams&, std::shared_ptr<Responder>)>
            handler);

    void route(Method method, std::string_view pattern,
        std::function<Response(const Request&, const RouteParams&)> handler);

    void operator()(const Request& request, std::shared_ptr<Responder>) const;

private:
    struct Route {
        struct Pattern {
            struct Part {
                enum class Type {
                    Literal,
                    Placeholder,
                    PlaceholderPath,
                };

                Type type;
                std::string_view str;
            };

            std::string pattern;
            std::vector<Part> parts;

            static Pattern parse(std::string_view str);

            std::optional<RouteParams> match(std::string_view urlPath) const;
        };

        Pattern pattern;
        Method method;
        std::function<void(const Request&, const RouteParams&, std::shared_ptr<Responder>)> handler;
    };

    std::vector<Route> routes_;
};
