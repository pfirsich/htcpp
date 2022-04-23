#pragma once

#include <memory>
#include <string>

#include <openssl/ssl.h>

// Must be at least 1.1.1
static_assert(OPENSSL_VERSION_NUMBER >= 10101000);

// No init function necessary anymore
// https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_init_ssl.html
// As of version 1.1.0 OpenSSL will automatically allocate all resources that it needs so no
// explicit initialisation is required. Similarly it will also automatically deinitialise as
// required.

// If an error occured, call this or ERR_clear_error() to clear the error queue
std::string getSslErrorString();

class SslContext {
public:
    SslContext();
    ~SslContext();

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
    static SslContextManager& instance();

    void init(const std::string& certChainPath, const std::string& keyPath);

    std::shared_ptr<SslContext> getCurrentContext();

private:
    SslContextManager() = default;
    SslContextManager(const SslContextManager&) = delete;
    SslContextManager(SslContextManager&&) = delete;
    SslContextManager& operator=(const SslContextManager&) = delete;
    SslContextManager& operator=(SslContextManager&&) = delete;

    std::string certChainPath_;
    std::string keyPath_;
    std::shared_ptr<SslContext> currentContext_;
};
