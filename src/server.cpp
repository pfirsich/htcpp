#include "server.hpp"

#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

Fd createTcpListenSocket(uint16_t listenPort, uint32_t listenAddr, int backlog)
{
    Fd fd { ::socket(AF_INET, SOCK_STREAM, 0) };
    if (fd == -1)
        return fd;

    sockaddr_in addr;
    ::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = listenAddr;
    addr.sin_port = htons(listenPort);

    const int reuse = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        slog::error("Could not set sockopt SO_REUSEADDR");
        return Fd {};
    }

    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        slog::error("Could not bind to port ", listenPort);
        return Fd {};
    }

    if (::listen(fd, backlog) == -1) {
        slog::error("Could not listen on socket");
        return Fd {};
    }

    return fd;
}
