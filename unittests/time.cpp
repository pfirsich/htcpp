#include "test.hpp"

#include "time.hpp"

TEST_CASE("TimePoint::parse")
{
    TEST_CHECK(!!TimePoint::parse("23:45"));
    TEST_CHECK(!!TimePoint::parse("23:45:12"));
}

TEST_CASE("TimePoint::parse fails")
{
    TEST_CHECK(!TimePoint::parse("01"));
    TEST_CHECK(!TimePoint::parse("010203"));
    TEST_CHECK(!TimePoint::parse("010203"));
    TEST_CHECK(!TimePoint::parse("01:02:a"));
    TEST_CHECK(!TimePoint::parse("24:05:06"));
    TEST_CHECK(!TimePoint::parse("23:60:06"));
    TEST_CHECK(!TimePoint::parse("23:03:60"));
}

TEST_CASE("TimePoint::getDurationUntil")
{
    TEST_CHECK(toString(TimePoint { 12, 4, 3 }.getDurationUntil({ 12, 5, 8 })) == "0d0h1m5s");
    // TEST_CHECK(toString(TimePoint { 23, 59, 59 }.getDurationUntil({ 0, 0, 0 })) == "0d0h0m1s");
}
