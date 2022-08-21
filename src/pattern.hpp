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
    static bool hasGroupReferences(std::string_view str);
    static std::string replaceGroupReferences(
        std::string_view str, const std::vector<std::string_view>& groups);

    MatchResult match(std::string_view str) const;

    size_t numCaptureGroups() const;

    bool isValidReplacementString(std::string_view str) const;

    const std::string& raw() const;

    bool isLiteral() const;
    bool isWildcard() const;

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

    bool isAnyOf() const;
    bool isLiteralPrefix() const;
    bool isAnyOfPrefix() const;
    bool isLiteralSuffix() const;
    bool isAnyOfSuffix() const;

    MatchResult genericMatch(std::string_view str) const;

    Type type_ = Type::Generic;
    std::string raw_;
    std::vector<Part> parts_;
};
