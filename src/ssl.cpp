#include "ssl.hpp"

#include <cassert>

#include <openssl/bio.h>
#include <openssl/err.h>

#include "log.hpp"

std::string getSslErrorString()
{
    auto err = ERR_get_error();
    char buf[256];
    std::string errStr = "no error";
    size_t num = 0;
    while (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        if (num == 0) {
            errStr = "";
        } else {
            errStr.append(", ");
        }
        errStr.append(buf);
        err = ERR_get_error();
        ++num;
    }
    return errStr;
}

std::string sslErrorToString(int sslError)
{
    switch (sslError) {
    case SSL_ERROR_NONE:
        return "SSL_ERROR_NONE";
    case SSL_ERROR_SSL:
        return "SSL_ERROR_SSL";
    case SSL_ERROR_WANT_READ:
        return "SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_WRITE:
        return "SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
        return "SSL_ERROR_SYSCALL";
    case SSL_ERROR_ZERO_RETURN:
        return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_CONNECT:
        return "SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
        return "SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_ASYNC:
        return "SSL_ERROR_WANT_ASYNC";
    case SSL_ERROR_WANT_ASYNC_JOB:
        return "SSL_ERROR_WANT_ASYNC_JOB";
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
    default:
        return "Unknown (" + std::to_string(sslError) + ")";
    }
}

std::optional<SslContext> SslContext::load(
    const std::string& certChainPath, const std::string& keyPath)
{
    auto ctx = SslContext();
    if (!static_cast<SSL_CTX*>(ctx)) {
        return std::nullopt;
    }
    if (!ctx.init(certChainPath, keyPath)) {
        return std::nullopt;
    }
    return ctx;
}

// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_new.html
// TLS_method is the only one that should be used anymore
SslContext::SslContext()
    : ctx_(SSL_CTX_new(TLS_server_method()))
{
    if (!ctx_) {
        slog::error("Could not create SSL context: ", getSslErrorString());
        return;
    }
    if (SSL_CTX_set_min_proto_version(ctx_, TLS1_VERSION) != 1) {
        slog::error("Could not set minimum protocol version: ", getSslErrorString());
    }
}

SslContext::~SslContext()
{
    SSL_CTX_free(ctx_);
}

SslContext::SslContext(SslContext&& other)
    : ctx_(other.ctx_)
{
    other.ctx_ = nullptr;
}

SslContext& SslContext::operator=(SslContext&& other)
{
    ctx_ = other.ctx_;
    other.ctx_ = nullptr;
    return *this;
}

bool SslContext::init(const std::string& certChainPath, const std::string& keyPath)
{
    slog::info("Loading certificates from '", certChainPath, "'");
    assert(ctx_);
    if (SSL_CTX_use_certificate_chain_file(ctx_, certChainPath.c_str()) != 1) {
        slog::error("Could not load certificate chain file: ", getSslErrorString());
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx_, keyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        slog::error("Could not load private key file: ", getSslErrorString());
        return false;
    }

    if (SSL_CTX_check_private_key(ctx_) != 1) {
        slog::error("Certificate and private key do not match: ", getSslErrorString());
        return false;
    }
    return true;
}

SslContext::operator SSL_CTX*()
{
    return ctx_;
}

SslContextManager::SslContextManager(IoQueue& io, std::string certChainPath, std::string keyPath)
    : certChainPath_(std::move(certChainPath))
    , keyPath_(std::move(keyPath))
    , io_(io)
    , fileWatcher_(io)
{
    updateContext();
    // TODO: Cancel on destruction and take ownership of SslContextManager
    // for now we assume a SslContextManager lives forever
    fileWatcher_.watch(
        certChainPath_, [this](std::error_code ec, std::string_view) { fileWatcherCallback(ec); });
    fileWatcher_.watch(
        keyPath_, [this](std::error_code ec, std::string_view) { fileWatcherCallback(ec); });
}

void SslContextManager::fileWatcherCallback(std::error_code ec)
{
    if (ec) {
        slog::fatal("Error watching certificates: ", ec.message());
        std::exit(1);
    }
    // TODO: Introduce some delay so we don't reload the certificate twice, when both the
    // certificate chain file and the private key changed shortly after another.
    io_.async<std::optional<SslContext>>(
        [this]() -> std::optional<SslContext> {
            return SslContext::load(certChainPath_, keyPath_);
        },
        [this](std::error_code ec, std::optional<SslContext>&& context) -> void {
            if (ec) {
                slog::error("Error during certificate reload: ", ec.message());
            } else if (context) {
                currentContext_ = std::make_shared<SslContext>(std::move(*context));
            }
            // If context is empty, we already logged a message
        });
}

std::shared_ptr<SslContext> SslContextManager::getCurrentContext() const
{
    return currentContext_;
}

void SslContextManager::updateContext()
{
    auto ctx = SslContext::load(certChainPath_, keyPath_);
    if (!ctx) {
        return;
    }
    currentContext_ = std::make_shared<SslContext>(std::move(*ctx));
}

const char* OpenSslErrorCategory::name() const noexcept
{
    return "OpenSSL Error Category";
}

std::string OpenSslErrorCategory::message(int errorCode) const
{
    char buf[256];
    ERR_error_string_n(static_cast<unsigned long>(errorCode), buf, sizeof(buf));
    return buf;
}

std::error_code OpenSslErrorCategory::makeError(unsigned long err)
{
    return std::error_code { static_cast<int>(err), getOpenSslErrorCategory() };
}

OpenSslErrorCategory& getOpenSslErrorCategory()
{
    static OpenSslErrorCategory cat;
    return cat;
}

std::string toString(SslOperation op)
{
    switch (op) {
    case SslOperation::Read:
        return "SSL_read";
    case SslOperation::Write:
        return "SSL_write";
    case SslOperation::Shutdown:
        return "SSL_shutdown";
    default:
        return "Unknown (" + std::to_string(static_cast<int>(op)) + ")";
    }
}

SslConnection::SslConnection(IoQueue& io, int fd, std::shared_ptr<SslContext> context)
    : TcpConnection(io, fd)
    , ssl_(SSL_new(*context))
{
    if (!ssl_) {
        slog::error("Could not create SSL object: ", getSslErrorString());
        return;
    }

    // I think there is no reason not to have this? It should save memory.
    SSL_set_mode(ssl_, SSL_MODE_RELEASE_BUFFERS);

    BIO* internalBio = nullptr;
    BIO_new_bio_pair(&internalBio, 0, &externalBio_, 0);
    if (!internalBio || !externalBio_) {
        assert(!internalBio && !externalBio_);
        return;
    }
    SSL_set_bio(ssl_, internalBio, internalBio);

    // https://www.openssl.org/docs/man1.1.1/man3/SSL_set_connect_state.html
    // Even though it may be clear from the method chosen, whether client or server mode was
    // requested, the handshake routines must be explicitly set.
    // If SSL_is_server() is called before SSL_set_connect_state() or SSL_set_accept_state() is
    // called (either automatically or explicitly), the result depends on what method was used when
    // SSL_CTX was created with SSL_CTX_new(3). If a generic method or a dedicated server method was
    // passed to SSL_CTX_new(3), SSL_is_server() returns 1; otherwise, it returns 0.
    // => It's very weird that I have to do this, but it seems I do.
    if (SSL_is_server(ssl_)) {
        SSL_set_accept_state(ssl_);
    } else {
        SSL_set_connect_state(ssl_);
    }

    // https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
    // 16K is maximum TLS record size
    // but 17*1024 is default BIO size.
    recvBuffer_.resize(17 * 1024, 0);
    sendBuffer_.resize(17 * 1024, 0);

    /*
     * We don't have to do the handshake here manually:
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
     * "If necessary, a read function will negotiate a TLS/SSL session, if not already
     * explicitly performed by SSL_connect(3) or SSL_accept(3). If the peer requests a
     * re-negotiation, it will be performed transparently during the read function operation.""
     */
}

SslConnection::~SslConnection()
{
    SSL_free(ssl_);
    BIO_free(externalBio_);
}

bool SslConnection::setHostname(const std::string& hostname)
{
    assert(!SSL_is_server(ssl_));
    SSL_set_hostflags(ssl_, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!SSL_set1_host(ssl_, hostname.c_str())) {
        slog::error("Could not set hostname for validation");
        return false;
    }
    SSL_set_verify(ssl_, SSL_VERIFY_PEER, nullptr);
    // Judging from the docs for SSL_set_verify and SSL_VERIFY_PEER I don't have to check
    // SSL_get_verify_result when SSL_is_init_finished.
    return true;
}

void SslConnection::recv(void* buffer, size_t len, IoQueue::HandlerEcRes handler)
{
    startSslOperation(SslOperation::Read, buffer, len, std::move(handler));
}

void SslConnection::send(const void* buffer, size_t len, IoQueue::HandlerEcRes handler)
{
    // This const_cast is okay, because before this buffer is accessed, it's const_cast back to
    // `const void*` again.
    startSslOperation(SslOperation::Write, const_cast<void*>(buffer), len, std::move(handler));
}

void SslConnection::shutdown(IoQueue::HandlerEc handler)
{
    startSslOperation(SslOperation::Shutdown, nullptr, 0,
        [handler = std::move(handler)](std::error_code ec, int) { handler(ec); });
}

SslConnection::SslOperationResult SslConnection::performSslOperation(
    SslOperation op, SSL* ssl, void* buffer, int length)
{
    // Make sure the SSL_get_error below this gives us the most recent error
    ::ERR_clear_error();

    int result = 0;
    switch (op) {
    case SslOperation::Read:
        result = SSL_read(ssl, buffer, length);
        break;
    case SslOperation::Write:
        result = SSL_write(ssl, const_cast<const void*>(buffer), length);
        break;
    case SslOperation::Shutdown: {
        // If SSL_shutdown returns 0, you are supposed to not call SSL_get_error and SSL_read
        // all remaining data, then SSL_shutdown again.
        // This is a bit awkward to fit into the rest of the code,
        // so I borrow this from boost asio as well.
        result = SSL_shutdown(ssl);
        if (result == 0) {
            result = SSL_shutdown(ssl);
        }
        break;
    }
    default:
        std::abort();
    }

    const auto error = SSL_get_error(ssl, result);

    ::ERR_clear_error();

    return SslOperationResult { result, error };
}

void SslConnection::performSslOperation()
{
    const auto res = performSslOperation(state_.currentOp, ssl_, state_.buffer, state_.length);
    state_.lastResult = res.result;
    state_.lastError = res.error;
    processSslOperationResult(res);
}

void SslConnection::startSslOperation(
    SslOperation op, void* buffer, int length, IoQueue::HandlerEcRes handler)
{
    state_ = SslOperationState { std::move(handler), op, buffer, length };
    performSslOperation();
}

void SslConnection::updateSslOperation()
{
    if (state_.lastError == SSL_ERROR_NONE) {
        completeSslOperation(std::error_code {}, state_.lastResult);
    } else if (state_.lastError == SSL_ERROR_ZERO_RETURN) {
        completeSslOperation(std::error_code {}, 0);
    } else {
        performSslOperation();
    }
}

void SslConnection::completeSslOperation(std::error_code ec, int result)
{
    auto handler = std::move(state_.handler);
    // Handler needs to be released, so the Session can die, but we have to do it before we call the
    // handler, because it might start another SSL operation and we don't want to discard it
    // immediately.
    state_ = SslOperationState {};
    handler(ec, result);
}

void SslConnection::processSslOperationResult(const SslOperationResult& result)
{
    // Number of bytes that are waiting to be sent
    const auto pending = BIO_ctrl_pending(externalBio_);

    if (result.error == SSL_ERROR_SSL || result.error == SSL_ERROR_SYSCALL) {
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_get_error.html
        // "non-recoverable fatal error"
        // "no further I/O operations should be performed on the connection and SSL_shutdown
        // must not be called"
        const auto ec = OpenSslErrorCategory::makeError(ERR_peek_error());
        slog::debug("SSL Error ", sslErrorToString(result.error), " in ",
            toString(state_.currentOp), ": ", getSslErrorString());
        completeSslOperation(ec, -1);
    } else if (pending > 0 || result.error == SSL_ERROR_WANT_WRITE) {
        // Even if we are finished (SSL_ERROR_NONE, SSL_ERROR_ZERO_RETURN), we need to send out the
        // pending bytes.
        // If we can read or write (pending > 0 and SSL_ERROR_WANT_READ), we rather
        // write, because then we can proceed quicker (writing should mostly finish quicker than
        // reading).
        const auto readFromBio = BIO_read(externalBio_, sendBuffer_.data(), sendBuffer_.size());
        // Why would OpenSSL say WANT_WRITE if it has nothing to write?
        assert(readFromBio > 0);
        // This assert is preliminary
        assert(pending == static_cast<size_t>(readFromBio));

        io_.send(fd_, sendBuffer_.data(), readFromBio,
            [this, readFromBio](std::error_code ec, int sentBytes) {
                if (ec) {
                    slog::debug("Error in send (SSL): ", ec.message());
                    // Because a read error would result in a SSL_ERROR_SYSCALL if OpenSSL did
                    // the syscalls itself, we also should not call SSL_shutdown.
                    completeSslOperation(ec, -1);
                    return;
                }

                if (sentBytes == 0) {
                    completeSslOperation(std::error_code {}, 0);
                    return;
                }

                assert(readFromBio == sentBytes);
                updateSslOperation();
            });
    } else if (result.error == SSL_ERROR_WANT_READ) {
        io_.recv(
            fd_, recvBuffer_.data(), recvBuffer_.size(), [this](std::error_code ec, int readBytes) {
                if (ec) {
                    slog::debug("Error in recv (SSL): ", ec.message());
                    // See branch for SSL_ERROR_WANT_WRITE
                    completeSslOperation(ec, -1);
                    return;
                }

                if (readBytes == 0) {
                    completeSslOperation(std::error_code {}, 0);
                    return;
                }

                BIO_write(externalBio_, recvBuffer_.data(), readBytes);
                updateSslOperation();
            });
    } else if (result.error == SSL_ERROR_NONE) {
        completeSslOperation(std::error_code {}, result.result);
    } else if (result.error == SSL_ERROR_ZERO_RETURN) {
        // The remote peer closed the connection.
        completeSslOperation(std::error_code {}, 0);
    } else {
        const auto ec = OpenSslErrorCategory::makeError(ERR_peek_error());
        slog::error("Unexpected SSL error ", sslErrorToString(result.error), " in ",
            toString(state_.currentOp), ": ", getSslErrorString());
        completeSslOperation(ec, -1);
    }
}

SslConnectionFactory::SslConnectionFactory(
    IoQueue& io, std::string certChainPath, std::string keyPath)
    : contextManager(
        std::make_unique<SslContextManager>(io, std::move(certChainPath), std::move(keyPath)))
{
}
