#include <cpprom/cpprom.hpp>

/* https://prometheus.io/docs/practices/instrumentation/#inner-loops
 * Summary:
 * - Key metrics are performaned queries, errors, latency, number of req in progress
 * - Be consistent in whether you count queries when they start or when they end
 * - Every line of logging code should have a counter that is incremented
 * - Failures should be handled similarly to logging. Every time there is a failure, a counter
 *   should be incremented.
 * - Threadpools: number of queued requests, the number of threads in use, the total number of
 *   threads, the number of tasks processed, and how long they took. how long things were waiting in
 *   the queue.
 * - Caches: total queries, hits, overall latency. query count, errors and latency of whatever
 *   online-serving system the cache is in front of
 */
struct Metrics {
    cpprom::MetricFamily<cpprom::Counter>& connAccepted;
    cpprom::MetricFamily<cpprom::Counter>& connDropped;
    cpprom::MetricFamily<cpprom::Gauge>& connActive;

    cpprom::MetricFamily<cpprom::Counter>& reqsTotal;
    cpprom::MetricFamily<cpprom::Histogram>& reqHeaderSize;
    cpprom::MetricFamily<cpprom::Histogram>& reqBodySize;
    cpprom::MetricFamily<cpprom::Histogram>& reqDuration;

    cpprom::MetricFamily<cpprom::Counter>& respTotal;
    cpprom::MetricFamily<cpprom::Histogram>& respSize;

    cpprom::MetricFamily<cpprom::Counter>& acceptErrors;
    cpprom::MetricFamily<cpprom::Counter>& recvErrors;
    cpprom::MetricFamily<cpprom::Counter>& sendErrors;
    cpprom::MetricFamily<cpprom::Counter>& reqErrors;

    cpprom::MetricFamily<cpprom::Counter>& fileCacheQueries;
    cpprom::MetricFamily<cpprom::Counter>& fileCacheHits;
    cpprom::MetricFamily<cpprom::Counter>& fileCacheFailures;
    cpprom::MetricFamily<cpprom::Histogram>& fileReadDuration;

    cpprom::MetricFamily<cpprom::Gauge>& ioQueueOpsQueued;
    // cpprom::MetricFamily<cpprom::Histogram>& ioQueueOpDuration;

    static Metrics& get();
};
