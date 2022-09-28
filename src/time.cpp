#include "time.hpp"

#include <cassert>
#include <tuple>
#include <vector>

#include "string.hpp"

Duration Duration::normalized() const
{
    auto totalSeconds = toSeconds();
    const auto days = totalSeconds / 24 / 60 / 60;
    totalSeconds -= days * 24 * 60 * 60;
    const auto hours = totalSeconds / 60 / 60;
    totalSeconds -= hours * 60 * 60;
    const auto minutes = totalSeconds / 60;
    totalSeconds -= minutes * 60;
    const auto seconds = totalSeconds;
    return Duration { days, hours, minutes, seconds };
}

std::optional<Duration> Duration::parse(std::string_view str)
{
    if (str.size() < 2) {
        return std::nullopt;
    }

    const auto num = str.substr(0, str.size() - 1);
    const auto numVal = parseInt<uint32_t>(num);
    if (!numVal) {
        return std::nullopt;
    }

    switch (str.back()) {
    case 'd':
        return Duration::fromDays(*numVal);
    case 'h':
        return Duration::fromHours(*numVal);
    case 'm':
        return Duration::fromMinutes(*numVal);
    case 's':
        return Duration::fromSeconds(*numVal);
    default:
        return std::nullopt;
    }
}

Duration Duration::fromDays(uint32_t v)
{
    return Duration { v, 0, 0, 0 }.normalized();
}

Duration Duration::fromHours(uint32_t v)
{
    return Duration { 0, v, 0, 0 }.normalized();
}

Duration Duration::fromMinutes(uint32_t v)
{
    return Duration { 0, 0, v, 0 }.normalized();
}

Duration Duration::fromSeconds(uint32_t v)
{
    return Duration { 0, 0, 0, v }.normalized();
}

std::string toString(const Duration& d)
{
    return std::to_string(d.days) + "d" + std::to_string(d.hours) + "h" + std::to_string(d.minutes)
        + "m" + std::to_string(d.seconds) + "s";
}

bool operator<(const Duration& a, const Duration& b)
{
    const auto na = a.normalized();
    const auto nb = b.normalized();
    // It's much less code and much simpler this way
    return std::make_tuple(na.days, na.hours, na.minutes, na.seconds)
        < std::make_tuple(nb.days, nb.hours, nb.minutes, nb.seconds);
}

std::optional<TimePoint> TimePoint::parse(std::string_view str)
{
    if (str.size() < 3) {
        return std::nullopt;
    }

    const auto parts = split(str, ':');
    assert(parts.size() > 0);
    if (parts.size() < 2 || parts.size() > 3) {
        return std::nullopt;
    }

    std::vector<uint32_t> nums;
    for (const auto part : parts) {
        const auto n = parseInt<uint32_t>(part);
        if (!n) {
            return std::nullopt;
        }
        nums.push_back(*n);
    }

    assert(nums.size() == 2 || nums.size() == 3);
    if (nums[0] >= 24 || nums[1] >= 60) {
        return std::nullopt;
    }
    if (nums.size() == 2) {
        return TimePoint { nums[0], nums[1], 0 };
    } else if (nums.size() == 3) {
        if (nums[2] >= 60) {
            return std::nullopt;
        }
        return TimePoint { nums[0], nums[1], nums[2] };
    } else {
        return std::nullopt;
    }
}

Duration TimePoint::getDurationUntil(const TimePoint& other) const
{
    assert(hours < 24 && minutes < 60 && seconds < 60);
    assert(other.hours < 24 && other.minutes < 60 && other.seconds < 60);

    auto ds = static_cast<int>(other.seconds) - static_cast<int>(seconds);
    auto dm = static_cast<int>(other.minutes) - static_cast<int>(minutes);
    auto dh = static_cast<int>(other.hours) - static_cast<int>(hours);
    if (ds < 0) {
        ds += 60;
        assert(ds > 0 && ds < 60);
        dm -= 1;
    }
    if (dm < 0) {
        dm += 60;
        assert(dm > 0 && dm < 60);
        dh -= 1;
    }
    if (dh < 0) {
        dh += 24;
        assert(dh > 0 && dh < 24);
    }

    return Duration { 0, static_cast<uint32_t>(dh), static_cast<uint32_t>(dm),
        static_cast<uint32_t>(ds) }
        .normalized();
}

std::string toString(const TimePoint& tp)
{
    return rjust(std::to_string(tp.hours), 2, '0') + ":" + rjust(std::to_string(tp.minutes), 2, '0')
        + ":" + rjust(std::to_string(tp.seconds), 2, '0');
}
