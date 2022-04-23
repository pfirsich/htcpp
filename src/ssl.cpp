#include "ssl.hpp"

#include <cassert>
#include <iostream>

#include <openssl/err.h>

std::string getSslErrorString()
{
    auto err = ERR_get_error();
    char buf[256];
    std::string errStr = "no error";
    size_t num = 0;
    while (err != 0) {
        ++num;
        ERR_error_string_n(err, buf, sizeof(buf));
        if (num > 1) {
            errStr.append(", ");
        }
        errStr.append(buf);
        err = ERR_get_error();
    }
    return errStr;
}

// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_new.html
// TLS_method is the only one that should be used anymore
SslContext::SslContext()
    : ctx_(SSL_CTX_new(TLS_server_method()))
{
    if (!ctx_) {
        std::cerr << "Could not create SSL context: " << getSslErrorString() << std::endl;
        return;
    }
    if (SSL_CTX_set_min_proto_version(ctx_, TLS1_VERSION) != 1) {
        std::cerr << "Could not set minimum protocol version: " << getSslErrorString() << std::endl;
    }
}

SslContext::~SslContext()
{
    SSL_CTX_free(ctx_);
}

// PEM cert chain file and PEM private key without password is enough to test
// and also what certbot spits out, so it is all I need.
bool SslContext::init(const std::string& certChainPath, const std::string& keyPath)
{
    std::cout << "Loading certificates from " << certChainPath << std::endl;
    assert(ctx_);
    if (SSL_CTX_use_certificate_chain_file(ctx_, certChainPath.c_str()) != 1) {
        std::cerr << "Could not load certificate chain file: " << getSslErrorString() << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx_, keyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cerr << "Could not load private key file: " << getSslErrorString() << std::endl;
        return false;
    }

    if (SSL_CTX_check_private_key(ctx_) != 1) {
        std::cerr << "Certificate and private key do not match: " << getSslErrorString()
                  << std::endl;
        return false;
    }
    return true;
}

SslContext::operator SSL_CTX*()
{
    return ctx_;
}

SslContextManager& SslContextManager::instance()
{
    static SslContextManager inst;
    return inst;
}

void SslContextManager::init(const std::string& certChainPath, const std::string& keyPath)
{
    certChainPath_ = certChainPath;
    keyPath_ = keyPath;
}

std::shared_ptr<SslContext> SslContextManager::getCurrentContext()
{
    assert(!certChainPath_.empty() && !keyPath_.empty());

    if (!currentContext_) {
        currentContext_ = std::make_shared<SslContext>();
        assert(static_cast<SSL_CTX*>(*currentContext_)); // Handle this later
        const auto res = currentContext_->init(certChainPath_, keyPath_);
        assert(res); // Handle this later also
    }
    return currentContext_;
}
