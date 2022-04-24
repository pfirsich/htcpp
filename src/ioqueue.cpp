#include "ioqueue.hpp"

IoQueue::IoQueue(size_t size)
    : completionHandlers_(size)
{
    ring_.init(size);
    if (!(ring_.getParams().features & IORING_FEAT_NODROP)) {
        std::cerr << "io_uring does not support NODROP" << std::endl;
        std::exit(1);
    }
    if (!(ring_.getParams().features & IORING_FEAT_SUBMIT_STABLE)) {
        std::cerr << "io_uring does not support SUBMIT_STABLE" << std::endl;
        std::exit(1);
    }
}

bool IoQueue::write(int fd, const void* buf, size_t len, HandlerEcRes cb)
{
    // printf("queue buf: %p, size: %lu\n", buf, len);
    return addSqe(ring_.prepareWrite(fd, buf, len), std::move(cb));
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
        } else {
            std::cout << "ignored" << std::endl;
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
