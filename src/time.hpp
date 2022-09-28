#pragma once

#include <optional>
#include <string_view>

struct Duration {
    uint32_t days = 0;
    uint32_t hours = 0;
    uint32_t minutes = 0;
    uint32_t seconds = 0;

    constexpr uint32_t toSeconds() const
    {
        return seconds + 60 * (minutes + 60 * (hours + 24 * days));
    }

    constexpr uint32_t toMinutes() const { return toSeconds() / 60; }
    constexpr uint32_t toHours() const { return toMinutes() / 60; }
    constexpr uint32_t toDays() const { return toHours() / 24; }

    Duration normalized() const;

    static std::optional<Duration> parse(std::string_view str);
    static Duration fromDays(uint32_t d);
    static Duration fromHours(uint32_t h);
    static Duration fromMinutes(uint32_t m);
    static Duration fromSeconds(uint32_t s);
};

std::string toString(const Duration& d);

bool operator<(const Duration& a, const Duration& b);

struct TimePoint {
    uint32_t hours;
    uint32_t minutes;
    uint32_t seconds = 0;

    Duration getDurationUntil(const TimePoint& until) const;
    static std::optional<TimePoint> parse(std::string_view str);
};

std::string toString(const TimePoint& d);
