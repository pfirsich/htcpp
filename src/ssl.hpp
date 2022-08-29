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
    static std::unique_ptr<SslContext> createServer(
        const std::string& certChainPath, const std::string& keyPath);
    static std::unique_ptr<SslContext> createClient();

    enum class Mode { Invalid = 0, Client, Server };

    SslContext(Mode mode);
    ~SslContext();
    SslContext(SslContext&) = delete;
    SslContext& operator=(SslContext&) = delete;
    SslContext(SslContext&&);
    SslContext& operator=(SslContext&&);

    // The cert chain file and key file must be PEM files without a password.
    // This is enough because I can test with it and it is also what certbot spits out.
    bool initServer(const std::string& certChainPath, const std::string& keyPath);
    bool initClient();

    operator SSL_CTX*();

private:
    SSL_CTX* ctx_;
};

class SslServerContextManager {
public:
    SslServerContextManager(IoQueue& io, std::string certChainPath, std::string keyPath);

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

class SslClientContextManager {
public:
    SslClientContextManager();

    std::shared_ptr<SslContext> getCurrentContext() const;

private:
    std::shared_ptr<SslContext> currentContext_;
};

struct OpenSslErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override;
    std::string message(int errorCode) const override;

    static std::error_code makeError(unsigned long err);
};

OpenSslErrorCategory& getOpenSslErrorCategory();

enum class SslOperation { Invalid = 0, Read, Write, Shutdown };
std::string toString(SslOperation op);

// This whole thing is *heavily* inspired by what Boost ASIO is doing
class SslConnection : public TcpConnection {
public:
    SslConnection(IoQueue& io, int fd, std::shared_ptr<SslContext> context);
    ~SslConnection();

    // Not movable or copyable, because pointers to it are captured in lambdas
    SslConnection(SslConnection&&) = delete;
    SslConnection(const SslConnection&) = delete;
    SslConnection& operator=(const SslConnection&) = delete;
    SslConnection& operator=(SslConnection&&) = delete;

    // For hostname validation (only applicable to client connection)
    bool setHostname(const std::string& hostname);

    // If a handler of any of these three functions comes back with an error,
    // don't do any other IO on the socket and do not call shutdown (just close it).
    void recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler);
    void shutdown(IoQueue::HandlerEc handler);

private:
    struct SslOperationResult {
        int result;
        int error;
    };

    // There is only one of these, but I think it's nicer to contain it
    struct SslOperationState {
        IoQueue::HandlerEcRes handler = nullptr;
        SslOperation currentOp = SslOperation::Invalid;
        void* buffer = nullptr;
        int length = 0;
        int lastResult = 0;
        int lastError = 0;
    };

    static SslOperationResult performSslOperation(
        SslOperation op, SSL* ssl, void* buffer, int length);

    void startSslOperation(
        SslOperation op, void* buffer, int length, IoQueue::HandlerEcRes handler);
    void performSslOperation();
    void processSslOperationResult(const SslOperationResult& result);
    void updateSslOperation();
    void completeSslOperation(std::error_code ec, int result);

    SSL* ssl_;
    BIO* externalBio_ = nullptr;
    std::vector<char> recvBuffer_;
    std::vector<char> sendBuffer_;
    SslOperationState state_;
};

template <typename ContextManager>
struct SslConnectionFactory {
    using Connection = SslConnection;

    std::unique_ptr<ContextManager> contextManager;

    template <typename... Args>
    SslConnectionFactory(Args&&... args)
        : contextManager(std::make_unique<ContextManager>(std::forward<Args>(args)...))
    {
    }

    std::unique_ptr<Connection> create(IoQueue& io, int fd)
    {
        auto context = contextManager->getCurrentContext();
        return context ? std::make_unique<Connection>(io, fd, std::move(context)) : nullptr;
    }
};

using SslClientConnectionFactory = SslConnectionFactory<SslClientContextManager>;
using SslServerConnectionFactory = SslConnectionFactory<SslServerContextManager>;
