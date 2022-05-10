#include "stats.hpp"

Stats& Stats::get()
{
    static Stats stats;
    return stats;
}
