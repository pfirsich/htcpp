#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

class Pattern {
public:
    struct MatchResult {
        bool match;
        std::vector<std::string_view> groups = {}; // just wildcards for now
    };

    static std::optional<Pattern> create(std::string_view str);

    MatchResult match(std::string_view str) const;

private:
    enum class Type {
        Invalid = 0,
        Literal,
        AnyOf,
        Wildcard,
        LiteralPrefix,
        AnyOfPrefix,
        LiteralSuffix,
        AnyOfSuffix,
        Generic,
    };

    struct Literal {
        std::string str;
    };

    struct AnyOf {
        std::vector<std::string> options;
    };

    struct Wildcard { };

    using Part = std::variant<Literal, AnyOf, Wildcard>;

    Pattern() = default;

    bool isLiteral() const;
    bool isAnyOf() const;
    bool isWildcard() const;
    bool isLiteralPrefix() const;
    bool isAnyOfPrefix() const;
    bool isLiteralSuffix() const;
    bool isAnyOfSuffix() const;

    MatchResult genericMatch(std::string_view str) const;

    Type type_ = Type::Generic;
    std::vector<Part> parts_;
};
