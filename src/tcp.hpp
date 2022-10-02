#pragma once

#include <memory>

#include <ioqueue.hpp>

class TcpConnection {
public:
    TcpConnection(IoQueue& io, int fd);

    void recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void recv(void* buffer, size_t len, IoQueue::Timespec* timeout, IoQueue::HandlerEcRes handler);
    void send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void send(
        const void* buffer, size_t len, IoQueue::Timespec* timeout, IoQueue::HandlerEcRes handler);
    void shutdown(IoQueue::HandlerEc handler);
    void close();

protected:
    IoQueue& io_;
    int fd_;
};

struct TcpConnectionFactory {
    using Connection = TcpConnection;

    std::unique_ptr<Connection> create(IoQueue& io, int fd)
    {
        return std::make_unique<Connection>(io, fd);
    }
};
