#pragma once

#include <memory>
#include <string>

#include <openssl/ssl.h>

#include "filewatcher.hpp"
#include "tcp.hpp"

// Must be at least 1.1.1
static_assert(OPENSSL_VERSION_NUMBER >= 10101000);

// No init function necessary anymore
// https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_init_ssl.html
// As of version 1.1.0 OpenSSL will automatically allocate all resources that it needs so no
// explicit initialisation is required. Similarly it will also automatically deinitialise as
// required.

// If an error occured, call this or ERR_clear_error() to clear the error queue
std::string getSslErrorString();

std::string sslErrorToString(int sslError);

class SslContext {
public:
    static std::optional<SslContext> load(
        const std::string& certChainPath, const std::string& keyPath);

    SslContext();
    ~SslContext();
    SslContext(SslContext&) = delete;
    SslContext& operator=(SslContext&) = delete;
    SslContext(SslContext&&);
    SslContext& operator=(SslContext&&);

    // The cert chain file and key file must be PEM files without a password.
    // This is enough because I can test with it and it is also what certbot spits out.
    bool init(const std::string& certChainPath, const std::string& keyPath);

    operator SSL_CTX*();

private:
    SSL_CTX* ctx_;
};

// This being a Singleton is kind of lame, but it's good enough.
// Later this thing should recreate contexts, when the certificates get renewed
class SslContextManager {
public:
    SslContextManager(IoQueue& io, std::string certChainPath, std::string keyPath);

    std::shared_ptr<SslContext> getCurrentContext() const;

private:
    void updateContext();

    void fileWatcherCallback(std::error_code ec);

    std::string certChainPath_;
    std::string keyPath_;
    std::shared_ptr<SslContext> currentContext_;
    IoQueue& io_;
    FileWatcher fileWatcher_;
};

struct OpenSslErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override;
    std::string message(int errorCode) const override;

    static std::error_code makeError(unsigned long err);
};

OpenSslErrorCategory& getOpenSslErrorCategory();

enum class SslOperation { Read, Write, Shutdown };
std::string toString(SslOperation op);

template <SslOperation Op>
struct SslOperationFunc;

template <>
struct SslOperationFunc<SslOperation::Read> {
    int operator()(SSL* ssl, void* buffer, int length);
};

template <>
struct SslOperationFunc<SslOperation::Write> {
    int operator()(SSL* ssl, void* buffer, int length);
};

template <>
struct SslOperationFunc<SslOperation::Shutdown> {
    int operator()(SSL* ssl, void*, int);
};

// This whole thing is *heavily* inspired by what Boost ASIO is doing
class SslConnection : public TcpConnection {
public:
    SslConnection(IoQueue& io, int fd, std::shared_ptr<SslContext> context);
    // Note: This class is not actually movable (because it's captured in lambdas), but it can be
    // moved before any operation is done on it. And we need that.
    SslConnection(SslConnection&&);
    ~SslConnection();

    SslConnection(const SslConnection&) = delete;
    SslConnection& operator=(const SslConnection&) = delete;
    SslConnection& operator=(SslConnection&&) = delete;

    // If a handler of any of these three functions comes back with an error,
    // don't do any other IO on the socket and do not call shutdown (just close it).
    void recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void shutdown(IoQueue::HandlerEc handler);

private:
    template <SslOperation Op>
    void performSslOperation(void* buffer, size_t length, IoQueue::HandlerEcRes handler);

    SSL* ssl_;
    BIO* externalBio_ = nullptr;
    std::vector<char> recvBuffer_;
    std::vector<char> sendBuffer_;
};

struct SslConnectionFactory {
    using Connection = SslConnection;

    // SslContextManager is not movable, because FileWatcher isn't (for good reason)
    std::unique_ptr<SslContextManager> contextManager;

    SslConnectionFactory(IoQueue& io, std::string certChainPath, std::string keyPath);

    Connection create(IoQueue& io, int fd)
    {
        return Connection(io, fd, contextManager->getCurrentContext());
    }
};
