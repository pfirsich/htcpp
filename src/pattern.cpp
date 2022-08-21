#include "pattern.hpp"

#include <cassert>

#include "log.hpp"
#include "string.hpp"

std::optional<Pattern> Pattern::create(std::string_view str)
{
    Pattern ret;
    ret.raw_ = std::string(str);

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

bool Pattern::hasGroupReferences(std::string_view str)
{
    return str.find('$') != std::string_view::npos;
}

std::string Pattern::replaceGroupReferences(
    std::string_view str, const std::vector<std::string_view>& groups)
{
    assert(groups.size() < 10);
    std::string ret;
    ret.reserve(256);
    size_t cursor = 0;
    while (cursor < str.size()) {
        const auto marker = str.find('$', cursor);
        if (marker == std::string_view::npos) {
            ret.append(str.substr(cursor));
            break;
        } else {
            ret.append(str.substr(cursor, marker - cursor));
        }

        if (marker + 1 < str.size() && str[marker + 1] != '0' && isDigit(str[marker + 1])) {
            assert(str[marker + 1] >= '1');
            const auto idx = static_cast<size_t>(str[marker + 1] - '1');
            if (idx < groups.size()) {
                ret.append(groups[idx]);
            }
            cursor = marker + 2;
        } else {
            ret.push_back('$');
            cursor = marker + 1;
        }
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

size_t Pattern::numCaptureGroups() const
{
    size_t n = 0;
    for (const auto& part : parts_) {
        if (std::holds_alternative<Wildcard>(part)) {
            n++;
        }
    }
    return n;
}

bool Pattern::isValidReplacementString(std::string_view str) const
{
    const auto numGroups = numCaptureGroups();
    size_t cursor = 0;
    while (cursor < str.size()) {
        const auto marker = str.find('$', cursor);
        if (marker == std::string_view::npos) {
            break;
        }

        if (marker + 1 < str.size() && isDigit(str[marker + 1])) {
            if (str[marker + 1] == '0') {
                slog::info("'$0' is invalid. The first group is adressed by '$1'");
                return false;
            }
            assert(str[marker + 1] >= '1');
            const auto idx = static_cast<size_t>(str[marker + 1] - '1');
            if (idx >= numGroups) {
                slog::error("'", str.substr(marker, 2), "' is out of bounds. Pattern only has ",
                    numGroups, " groups");
                return false;
            }
            cursor = marker + 2;
        } else {
            cursor = marker + 1;
        }
    }
    return true;
}

const std::string& Pattern::raw() const
{
    return raw_;
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
