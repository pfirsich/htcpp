#pragma once

#include <cstdint>

class TokenBucket {
public:
    TokenBucket(double capacity, double fillRate);

    bool pull(double tokens = 1.0);

    void update();

    double getLevel() const;

    uint64_t getLastUpdate() const;

private:
    double capacity_;
    double fillRate_;
    double level_;
    uint64_t lastUpdate_;
};
