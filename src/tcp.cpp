#include "tcp.hpp"

TcpConnection::TcpConnection(IoQueue& io, int fd)
    : io_(io)
    , fd_(fd)
{
}

void TcpConnection::recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler)
{
    io_.recv(fd_, buffer, len, std::move(handler));
}

void TcpConnection::recv(
    void* buffer, size_t len, IoQueue::Timespec* timeout, IoQueue::HandlerEcRes handler)
{
    io_.recv(fd_, buffer, len, timeout, true, std::move(handler));
}

void TcpConnection::send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler)
{
    io_.send(fd_, buffer, len, std::move(handler));
}

void TcpConnection::send(
    const void* buffer, size_t len, IoQueue::Timespec* timeout, IoQueue::HandlerEcRes handler)
{
    io_.send(fd_, buffer, len, timeout, true, std::move(handler));
}

void TcpConnection::shutdown(IoQueue::HandlerEc handler)
{
    io_.shutdown(fd_, SHUT_RDWR, std::move(handler));
}

void TcpConnection::close()
{
    io_.close(fd_, [](std::error_code /*ec*/) {});
}
