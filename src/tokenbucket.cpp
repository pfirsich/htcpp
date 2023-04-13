#include "tokenbucket.hpp"

#include "util.hpp"

TokenBucket::TokenBucket(double capacity, double fillRate)
    : capacity_(capacity)
    , fillRate_(fillRate)
    , level_(capacity)
    , lastUpdate_(nowMillis())
{
}

bool TokenBucket::pull(double tokens)
{
    update();
    if (level_ >= tokens) {
        level_ -= tokens;
        return true;
    }
    return false;
}

void TokenBucket::update()
{
    const auto now = nowMillis();
    // I use doubles so that you don't get rejected if the bucket is empty, the fill rate is 1
    // and you attempt to request the page every 500ms.
    // With integers, this would just update lastUpdate_ every time and increment level_ by nothing.
    level_ += (now - lastUpdate_) * fillRate_ / 1000.0;
    level_ = std::min(level_, capacity_);
    lastUpdate_ = now;
}

double TokenBucket::getLevel() const
{
    return level_;
}

uint64_t TokenBucket::getLastUpdate() const
{
    return lastUpdate_;
}
