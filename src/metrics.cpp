#include "metrics.hpp"

#include <cpprom/processmetrics.hpp>

Metrics& Metrics::get()
{
    static auto& reg = cpprom::Registry::getDefault();
    // Process metrics are currently disabled, because they block
    //.registerCollector(cpprom::makeProcessMetricsCollector());
    static auto durationBuckets = cpprom::Histogram::defaultBuckets();
    static auto sizeBuckets = cpprom::Histogram::exponentialBuckets(256.0, 4.0, 7);
    static Metrics metrics {
        reg.counter("htcpp_connections_accepted", {}, "Number of connections accepted"),
        reg.counter("htcpp_connections_dropped", {}, "Number of connections dropped"),
        reg.gauge("htcpp_connections_active", {}, "Number of active connections"),

        reg.counter("htcpp_requests_total", { "method", "url" }, "Number of received requests"),
        reg.histogram("htcpp_request_header_size_bytes", { "method", "url" }, sizeBuckets,
            "Request header size"),
        reg.histogram(
            "htcpp_request_body_size_bytes", { "method", "url" }, sizeBuckets, "Request body size"),
        reg.histogram("htcpp_request_duration_seconds", { "method", "url" }, durationBuckets,
            "Time from first recv until after last send"),

        reg.counter(
            "htcpp_responses_total", { "method", "url", "status" }, "Number of sent responses"),
        reg.histogram("htcpp_response_size_bytes", { "method", "url", "status" }, sizeBuckets,
            "Response size in bytes"),

        reg.counter("htcpp_accept_errors_total", { "errno" }, "Number of errors in accept"),
        reg.counter("htcpp_recv_errors_total", { "errno" }, "Number of errors in recv"),
        reg.counter("htcpp_send_errors_total", { "errno" }, "Number of errors in send"),
        reg.counter(
            "htcpp_send_errors_total", { "errno" }, "Number of errors while processing request"),

        reg.counter("htcpp_filecache_queries_total", { "path" },
            "Number of queries towards the file cache"),
        reg.counter("htcpp_filecache_failures_total", { "path" },
            "Number of times the file cache could not load a file"),
        reg.histogram(
            "htcpp_file_read_duration", { "path" }, durationBuckets, "Time to read a file"),

        reg.gauge("htcpp_io_queued_total", { /*"op"*/ },
            "Number of operations currently queued in the IO queue"),
    };
    return metrics;
}
