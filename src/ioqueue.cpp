#include "ioqueue.hpp"

#include "log.hpp"
#include "util.hpp"

IoQueue::IoQueue(size_t size)
    : completionHandlers_(size)
{
    if (!ring_.init(size)) {
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

bool IoQueue::accept(int fd, sockaddr_in* addr, HandlerEcRes cb)
{
    socklen_t addrlen = 0;
    return addSqe(
        ring_.prepareAccept(fd, reinterpret_cast<sockaddr*>(addr), &addrlen), std::move(cb));
}

bool IoQueue::send(int sockfd, const void* buf, size_t len, HandlerEcRes cb)
{
    return addSqe(ring_.prepareSend(sockfd, buf, len), std::move(cb));
}

bool IoQueue::recv(int sockfd, void* buf, size_t len, HandlerEcRes cb)
{
    return addSqe(ring_.prepareRecv(sockfd, buf, len), std::move(cb));
}

bool IoQueue::recv(int sockfd, void* buf, size_t len, uint64_t timeoutMs, HandlerEcRes cb)
{
    return addSqe(ring_.prepareRecv(sockfd, buf, len), timeoutMs, std::move(cb));
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

void IoQueue::run()
{
    while (true) {
        const auto cqe = ring_.waitCqe();
        assert(cqe);

        if (cqe->user_data != Ignore) {
            assert(completionHandlers_.contains(cqe->user_data));
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
    sqe->user_data = addHandler(std::move(cb));
    ring_.submitSqes();
    return true;
}

template bool IoQueue::addSqe<IoQueue::HandlerEc>(io_uring_sqe* sqe, IoQueue::HandlerEc cb);
template bool IoQueue::addSqe<IoQueue::HandlerEcRes>(io_uring_sqe* sqe, IoQueue::HandlerEcRes cb);

template <typename Callback>
bool IoQueue::addSqe(io_uring_sqe* sqe, size_t timeoutMs, Callback cb)
{
    if (!sqe) {
        slog::warning("io_uring full");
        return false;
    }
    sqe->user_data = addHandler(std::move(cb));
    sqe->flags |= IOSQE_IO_LINK;
    __kernel_timespec ts;
    ts.tv_sec = timeoutMs / 1000;
    ts.tv_nsec = (timeoutMs % 1000) * 1000 * 1000;
    auto timeoutSqe = ring_.prepareLinkTimeout(&ts);
    timeoutSqe->user_data = Ignore;
    ring_.submitSqes();
    return true;
}

template bool IoQueue::addSqe<IoQueue::HandlerEc>(
    io_uring_sqe* sqe, size_t timeoutMs, IoQueue::HandlerEc cb);
template bool IoQueue::addSqe<IoQueue::HandlerEcRes>(
    io_uring_sqe* sqe, size_t timeoutMs, IoQueue::HandlerEcRes cb);
