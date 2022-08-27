#include "ioqueue.hpp"

#include <time.h>

#include <sys/eventfd.h>
#include <unistd.h>

#include "log.hpp"
#include "metrics.hpp"
#include "util.hpp"

void IoQueue::setRelativeTimeout(Timespec* ts, uint64_t milliseconds)
{
    ts->tv_sec = milliseconds / 1000;
    ts->tv_nsec = (milliseconds % 1000) * 1000 * 1000;
}

void IoQueue::setAbsoluteTimeout(Timespec* ts, uint64_t milliseconds)
{
    ::timespec nowTs;
    ::clock_gettime(CLOCK_MONOTONIC, &nowTs);
    ts->tv_sec = nowTs.tv_sec + milliseconds / 1000;
    ts->tv_nsec = nowTs.tv_nsec + (milliseconds % 1000) * 1000 * 1000;
    ts->tv_sec += ts->tv_nsec / (1000 * 1000 * 1000);
    ts->tv_nsec = ts->tv_nsec % (1000 * 1000 * 1000);
}

IoQueue::IoQueue(size_t size, bool submissionQueuePolling)
    : completionHandlers_(size)
{
    if (!ring_.init(size, submissionQueuePolling)) {
        slog::fatal("Could not create io_uring: ", errnoToString(errno));
        std::exit(1);
    }
    if (!(ring_.getParams().features & IORING_FEAT_NODROP)) {
        slog::fatal("io_uring does not support NODROP");
        std::exit(1);
    }
    if (!(ring_.getParams().features & IORING_FEAT_SUBMIT_STABLE)) {
        slog::fatal("io_uring does not support SUBMIT_STABLE");
        std::exit(1);
    }
}

size_t IoQueue::getSize() const
{
    return ring_.getNumSqeEntries();
}

size_t IoQueue::getCapacity() const
{
    return ring_.getSqeCapacity();
}

bool IoQueue::accept(int fd, sockaddr_in* addr, socklen_t* addrlen, HandlerEcRes cb)
{
    return addSqe(
        ring_.prepareAccept(fd, reinterpret_cast<sockaddr*>(addr), addrlen), std::move(cb));
}

bool IoQueue::connect(int sockfd, const ::sockaddr* addr, socklen_t addrlen, HandlerEc cb)
{
    return addSqe(ring_.prepareConnect(sockfd, addr, addrlen), std::move(cb));
}

bool IoQueue::send(int sockfd, const void* buf, size_t len, HandlerEcRes cb)
{
    return addSqe(ring_.prepareSend(sockfd, buf, len), std::move(cb));
}

bool IoQueue::recv(int sockfd, void* buf, size_t len, HandlerEcRes cb)
{
    return addSqe(ring_.prepareRecv(sockfd, buf, len), std::move(cb));
}

bool IoQueue::recv(int sockfd, void* buf, size_t len, IoQueue::Timespec* timeout,
    bool timeoutIsAbsolute, HandlerEcRes cb)
{
    return addSqe(ring_.prepareRecv(sockfd, buf, len), timeout, timeoutIsAbsolute, std::move(cb));
}

bool IoQueue::read(int fd, void* buf, size_t count, HandlerEcRes cb)
{
    return addSqe(ring_.prepareRead(fd, buf, count), std::move(cb));
}

bool IoQueue::close(int fd, HandlerEc cb)
{
    return addSqe(ring_.prepareClose(fd), std::move(cb));
}

bool IoQueue::shutdown(int fd, int how, HandlerEc cb)
{
    return addSqe(ring_.prepareShutdown(fd, how), std::move(cb));
}

bool IoQueue::poll(int fd, short events, HandlerEcRes cb)
{
    return addSqe(ring_.preparePollAdd(fd, events), std::move(cb));
}

IoQueue::NotifyHandle::NotifyHandle(int fd)
    : fd_(fd)
{
}

IoQueue::NotifyHandle::operator bool() const
{
    return fd_ != -1;
}

void IoQueue::NotifyHandle::notify(uint64_t value)
{
    assert(fd_ != -1);
    const auto res = ::write(fd_, &value, sizeof(uint64_t));
    if (res != sizeof(uint64_t)) {
        // We cannot call the handler (can't reach it from here).
        // We cannot cancel or terminate the read somehow (no functionality like that yet).
        // If we close fd_, the read will be stuck forever (tried it out).
        // This is used for certificate reloading, so if this fails here, we will never update the
        // certificate, when we should.
        // It's also used for expensive async operations while handling HTTP requests and if we fail
        // here those requests would hang forever.
        // I think the right thing to do here is exit.
        slog::fatal("Error writing to eventfd: ",
            std::make_error_code(static_cast<std::errc>(errno)).message());
        std::exit(1);
    }
    fd_ = -1;
}

IoQueue::NotifyHandle IoQueue::wait(std::function<void(std::error_code, uint64_t)> cb)
{
    const auto fd = ::eventfd(0, 0);
    auto buf = std::make_shared<uint64_t>(0);
    auto bufData = buf.get();
    const auto res = read(fd, bufData, sizeof(uint64_t),
        [fd, buf = std::move(buf), cb = std::move(cb)](std::error_code ec, int res) {
            ::close(fd);
            if (ec) {
                cb(ec, 0);
            } else {
                // man 2 eventfd: Each successful read(2) returns an 8-byte integer.
                // The example does handle the case of res != 8, but I don't really know
                // what I am not sure what I should do in that case, so I assert for now.
                assert(res == sizeof(uint64_t));
                cb(std::error_code(), *buf);
            }
        });
    if (res) {
        return NotifyHandle { fd };
    } else {
        ::close(fd);
        return NotifyHandle { -1 };
    }
}

void IoQueue::run()
{
    while (completionHandlers_.size() > 0) {
        const auto res = ring_.submitSqes(1);
        if (res < 0) {
            slog::error("Error submitting SQEs: ", errnoToString(errno));
            continue;
        }
        const auto cqe = ring_.peekCqe();
        assert(cqe);

        if (cqe->user_data != Ignore) {
            assert(completionHandlers_.contains(cqe->user_data));
            Metrics::get().ioQueueOpsQueued.labels().dec();
            auto ch = std::move(completionHandlers_[cqe->user_data]);
            ch(cqe);
            completionHandlers_.remove(cqe->user_data);
            ring_.advanceCq();
        }
    }
}

size_t IoQueue::addHandler(HandlerEc&& cb)
{
    return completionHandlers_.emplace([cb = std::move(cb)](const io_uring_cqe* cqe) {
        if (cqe->res < 0) {
            cb(std::make_error_code(static_cast<std::errc>(-cqe->res)));
        } else {
            cb(std::error_code());
        }
    });
}

size_t IoQueue::addHandler(HandlerEcRes&& cb)
{
    return completionHandlers_.emplace([cb = std::move(cb)](const io_uring_cqe* cqe) {
        if (cqe->res < 0) {
            cb(std::make_error_code(static_cast<std::errc>(-cqe->res)), -1);
        } else {
            cb(std::error_code(), cqe->res);
        }
    });
}

template <typename Callback>
bool IoQueue::addSqe(io_uring_sqe* sqe, Callback cb)
{
    if (!sqe) {
        slog::warning("io_uring full");
        return false;
    }
    Metrics::get().ioQueueOpsQueued.labels().inc();
    sqe->user_data = addHandler(std::move(cb));
    return true;
}

template bool IoQueue::addSqe<IoQueue::HandlerEc>(io_uring_sqe* sqe, IoQueue::HandlerEc cb);
template bool IoQueue::addSqe<IoQueue::HandlerEcRes>(io_uring_sqe* sqe, IoQueue::HandlerEcRes cb);

template <typename Callback>
bool IoQueue::addSqe(io_uring_sqe* sqe, Timespec* timeout, bool timeoutIsAbsolute, Callback cb)
{
    if (!sqe) {
        slog::warning("io_uring full");
        return false;
    }
    sqe->user_data = addHandler(std::move(cb));
    sqe->flags |= IOSQE_IO_LINK;
    auto timeoutSqe = ring_.prepareLinkTimeout(timeout, timeoutIsAbsolute ? IORING_TIMEOUT_ABS : 0);
    timeoutSqe->user_data = Ignore;
    return true;
}

template bool IoQueue::addSqe<IoQueue::HandlerEc>(
    io_uring_sqe* sqe, Timespec* timeout, bool timeoutIsAbsolute, IoQueue::HandlerEc cb);
template bool IoQueue::addSqe<IoQueue::HandlerEcRes>(
    io_uring_sqe* sqe, Timespec* timeout, bool timeoutIsAbsolute, IoQueue::HandlerEcRes cb);
