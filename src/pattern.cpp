#include "pattern.hpp"

#include <cassert>

#include "log.hpp"
#include "string.hpp"

std::optional<Pattern> Pattern::create(std::string_view str)
{
    Pattern ret;

    size_t i = 0;
    while (i < str.size()) {
        if (str[i] == '*') {
            ret.parts_.push_back(Wildcard {});
            i++;
        } else if (str[i] == '{') {
            // not +1, because str might be too small
            const auto end = str.find('}', i);
            if (end == std::string_view::npos) {
                return std::nullopt;
            }
            const auto args = str.substr(i + 1, end - i - 1);
            const auto parts = split(args, ',');
            ret.parts_.push_back(AnyOf { std::vector<std::string>(parts.begin(), parts.end()) });
            i = end + 1;
        } else {
            const auto end = str.find_first_of("{*");
            ret.parts_.push_back(Literal { std::string(str.substr(i, end - i)) });
            i = end;
        }
    }

    if (ret.isLiteral()) {
        ret.type_ = Type::Literal;
    } else if (ret.isWildcard()) {
        ret.type_ = Type::Wildcard;
    } else if (ret.isAnyOf()) {
        ret.type_ = Type::AnyOf;
    } else if (ret.isLiteralPrefix()) {
        ret.type_ = Type::LiteralPrefix;
    } else if (ret.isAnyOfPrefix()) {
        ret.type_ = Type::AnyOfPrefix;
    } else if (ret.isLiteralSuffix()) {
        ret.type_ = Type::LiteralSuffix;
    } else if (ret.isAnyOfSuffix()) {
        ret.type_ = Type::AnyOfSuffix;
    } else {
        ret.type_ = Type::Generic;
    }

    return ret;
}

Pattern::MatchResult Pattern::match(std::string_view str) const
{
    switch (type_) {
    case Type::Literal:
        assert(isLiteral());
        return MatchResult { std::get<Literal>(parts_[0]).str == str };
    case Type::AnyOf: {
        for (const auto& opt : std::get<AnyOf>(parts_[0]).options) {
            if (str == opt) {
                return MatchResult { true };
            }
        }
        return MatchResult { false };
    }
    case Type::Wildcard:
        assert(isWildcard());
        return MatchResult { true, { str } };
    case Type::LiteralPrefix: {
        assert(isLiteralPrefix());
        const auto& literal = std::get<Literal>(parts_[0]);
        if (startsWith(str, literal.str)) {
            return MatchResult { true, { str.substr(literal.str.size()) } };
        }
        return MatchResult { false };
    }
    case Type::AnyOfPrefix: {
        assert(isAnyOfPrefix());
        const auto& anyof = std::get<AnyOf>(parts_[0]);
        for (const auto& opt : anyof.options) {
            if (startsWith(str, opt)) {
                return MatchResult { true, { str.substr(opt.size()) } };
            }
        }
        return MatchResult { false };
    }
    case Type::LiteralSuffix: {
        assert(isLiteralSuffix());
        const auto& literal = std::get<Literal>(parts_[1]);
        if (endsWith(str, literal.str)) {
            return MatchResult { true, { str.substr(0, str.size() - literal.str.size()) } };
        }
        return MatchResult { false };
    }
    case Type::AnyOfSuffix: {
        assert(isAnyOfSuffix());
        for (const auto& opt : std::get<AnyOf>(parts_[1]).options) {
            if (endsWith(str, opt)) {
                return MatchResult { true, { str.substr(0, str.size() - opt.size()) } };
            }
        }
        return MatchResult { false };
    }
    case Type::Generic:
        return genericMatch(str);
    default:
        assert(false && "Invalid Pattern Type");
        break;
    }
}

bool Pattern::isLiteral() const
{
    return parts_.size() == 1 && std::holds_alternative<Literal>(parts_[0]);
}

bool Pattern::isAnyOf() const
{
    return parts_.size() == 1 && std::holds_alternative<AnyOf>(parts_[0]);
}

bool Pattern::isWildcard() const
{
    return parts_.size() == 1 && std::holds_alternative<Wildcard>(parts_[0]);
}

bool Pattern::isLiteralPrefix() const
{
    return parts_.size() == 2 && std::holds_alternative<Literal>(parts_[0])
        && std::holds_alternative<Wildcard>(parts_[1]);
}

bool Pattern::isAnyOfPrefix() const
{
    return parts_.size() == 2 && std::holds_alternative<AnyOf>(parts_[0])
        && std::holds_alternative<Wildcard>(parts_[1]);
}

bool Pattern::isLiteralSuffix() const
{
    return parts_.size() == 2 && std::holds_alternative<Wildcard>(parts_[0])
        && std::holds_alternative<Literal>(parts_[1]);
}

bool Pattern::isAnyOfSuffix() const
{
    return parts_.size() == 2 && std::holds_alternative<Wildcard>(parts_[0])
        && std::holds_alternative<AnyOf>(parts_[1]);
}

Pattern::MatchResult Pattern::genericMatch(std::string_view /*str*/) const
{
    assert(false && "Not Implemented");
    return MatchResult { false };
}
