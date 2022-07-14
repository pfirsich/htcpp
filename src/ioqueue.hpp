#pragma once

#include <functional>
#include <future>
#include <limits>
#include <system_error>
#include <thread>

#include <netinet/in.h>

#include "iouring.hpp"
#include "log.hpp"
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

    IoQueue(size_t size = 1024, bool submissionQueuePolling = false);

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

    bool read(int fd, void* buf, size_t count, HandlerEcRes cb);

    bool close(int fd, HandlerEc cb);

    bool shutdown(int fd, int how, HandlerEc cb);

    bool poll(int fd, short events, HandlerEcRes cb);

    class NotifyHandle {
    public:
        NotifyHandle(int fd);
        ~NotifyHandle() = default;
        NotifyHandle(const NotifyHandle&) = delete;
        NotifyHandle& operator=(const NotifyHandle&) = delete;
        NotifyHandle(NotifyHandle&&) = default;
        NotifyHandle& operator=(NotifyHandle&&) = default;

        // wait might fail, in which case this will return false
        explicit operator bool() const;

        // This will do a write on an eventfd, but it will not do it asynchronously, because it was
        // introduced to be used from other threads (async below), which would require IoQueue to be
        // thread-safe which it is not (at all).
        // This means that if you do it from the thread that processes the IoQueue (the main
        // thread), you need to be aware that this might block (unlikely though).
        // Also this function must be called exactly once. If it is not called, the async read on
        // the eventfd will never terminate. If you call it more than once, there is no read queued
        // up, so this function will abort.
        void notify(uint64_t value = 1);

    private:
        int fd_;
    };

    // This is a wrapper of a subset of eventfd functionality.
    // The value passed to NotifyHandle::notify will be passed to the handler cb.
    NotifyHandle wait(std::function<void(std::error_code, uint64_t)> cb);

    template <typename Result>
    bool async(std::function<Result()> func, std::function<void(std::error_code, Result&&)> cb)
    {
        // std::function content needs to be copyable :)
        // Only a minimal amount of hair has been ripped out of my skull because of this.
        auto prom = std::make_shared<std::promise<Result>>();
        auto fut = std::make_shared<std::future<Result>>(prom->get_future());
        auto handle = wait(
            [fut = std::move(fut), cb = std::move(cb)](std::error_code ec, uint64_t) mutable {
                if (ec) {
                    cb(ec, Result());
                } else {
                    cb(std::error_code(), std::move(fut->get()));
                }
            });
        if (!handle) {
            return false;
        }

        // Simply detaching a thread is really not very clean, but it's easy and enough for my
        // current use cases.
        std::thread t(
            [func = std::move(func), prom = std::move(prom), handle = std::move(handle)]() mutable {
                prom->set_value(func());
                handle.notify();
            });
        t.detach();
        return true;
    }

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
