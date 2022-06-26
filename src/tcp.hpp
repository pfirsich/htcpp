#pragma once

#include <ioqueue.hpp>

class TcpConnection {
public:
    TcpConnection(IoQueue& io, int fd);

    void recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void recv(void* buffer, size_t len, IoQueue::Timespec* timeout, bool timeoutIsAbsolute,
        IoQueue::HandlerEcRes handler);
    void send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void shutdown(IoQueue::HandlerEc handler);
    void close();

protected:
    IoQueue& io_;
    int fd_;
};

struct TcpConnectionFactory {
    using Connection = TcpConnection;

    Connection create(IoQueue& io, int fd)
    {
        return Connection(io, fd);
    }
};
