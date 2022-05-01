#pragma once

#include <functional>
#include <limits>
#include <system_error>

#include <netinet/in.h>

#include "iouring.hpp"
#include "slotmap.hpp"

class IoQueue {
private:
    using CompletionHandler = std::function<void(const io_uring_cqe*)>;

    static constexpr auto Ignore = std::numeric_limits<uint64_t>::max();

public:
    using HandlerEc = std::function<void(std::error_code ec)>;
    using HandlerEcRes = std::function<void(std::error_code ec, int res)>;
    using Timespec = IoURing::Timespec;

    // These are both relative with respect to their arguments, but naming these is hard.
    static void setRelativeTimeout(Timespec* ts, uint64_t milliseconds);
    static void setAbsoluteTimeout(Timespec* ts, uint64_t milliseconds);

    IoQueue(size_t size = 1024);

    size_t getSize() const;

    size_t getCapacity() const;

    // res argument is socket fd
    bool accept(int fd, sockaddr_in* addr, socklen_t* addrlen, HandlerEcRes cb);

    // res argument is sent bytes
    bool send(int sockfd, const void* buf, size_t len, HandlerEcRes cb);

    // res argument is received bytes
    bool recv(int sockfd, void* buf, size_t len, HandlerEcRes cb);

    bool recv(int sockfd, void* buf, size_t len, Timespec* timeout, bool timeoutIsAbsolute,
        HandlerEcRes cb);

    bool close(int fd, HandlerEc cb);

    bool shutdown(int fd, int how, HandlerEc cb);

    bool poll(int fd, short events, HandlerEcRes cb);

    void run();

private:
    size_t addHandler(HandlerEc&& cb);
    size_t addHandler(HandlerEcRes&& cb);

    template <typename Callback>
    bool addSqe(io_uring_sqe* sqe, Callback cb);

    template <typename Callback>
    bool addSqe(io_uring_sqe* sqe, Timespec* timeout, bool timeoutIsAbsolute, Callback cb);

    IoURing ring_;
    SlotMap<CompletionHandler> completionHandlers_;
};
