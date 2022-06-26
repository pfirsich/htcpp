#include <cassert>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <memory>
#include <optional>

#include <openssl/err.h>
#include <openssl/ssl.h>

std::optional<std::string> readFile(const std::string& path)
{
    auto f = std::unique_ptr<FILE, decltype(&std::fclose)>(
        std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!f) {
        std::cerr << "Could not open file: '" << path << "'" << std::endl;
        return std::nullopt;
    }
    if (std::fseek(f.get(), 0, SEEK_END) != 0) {
        std::cerr << "Error seeking to end of file: '" << path << "'" << std::endl;
        return std::nullopt;
    }
    const auto size = std::ftell(f.get());
    if (size < 0) {
        std::cerr << "Error getting size of file: '" << path << "'" << std::endl;
        return std::nullopt;
    }
    if (std::fseek(f.get(), 0, SEEK_SET) != 0) {
        std::cerr << "Error seeking to start of file: '" << path << "'" << std::endl;
        return std::nullopt;
    }
    std::string buf(size, '\0');
    if (std::fread(buf.data(), 1, size, f.get()) != static_cast<size_t>(size)) {
        std::cerr << "Error reading file: '" << path << "'" << std::endl;
        return std::nullopt;
    }
    return buf;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "Usage: load_cert_sync <certfile> <privkeyfile>" << std::endl;
        return 1;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx);

    auto start = std::chrono::high_resolution_clock::now();
    const auto chainFileData = readFile(argv[1]).value();
    const auto keyFileData = readFile(argv[2]).value();
    std::cout << "File read duration: "
              << (std::chrono::high_resolution_clock::now() - start).count() / 1000 << std::endl;

    start = std::chrono::high_resolution_clock::now();

    // Certificate Chain
    // https://github.com/openssl/openssl/blob/8aaca20cf9996257d1ce2e6f4d3059b3698dde3d/ssl/ssl_rsa.c#L570
    auto chainBio = BIO_new_mem_buf(chainFileData.data(), chainFileData.size());
    assert(chainBio);
    auto cert = PEM_read_bio_X509_AUX(chainBio, nullptr, nullptr, nullptr);
    assert(cert);
    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        std::cerr << "Could not load certificate" << std::endl;
        return 1;
    }
    // SSL_CTX_clear_chain_certs vs. SSL_CTX_clear_extra_chain_certs?
    if (SSL_CTX_clear_chain_certs(ctx) != 1) {
        std::cerr << "Could not clear chain certs" << std::endl;
        return 1;
    }
    X509* ca;
    while ((ca = PEM_read_bio_X509(chainBio, nullptr, nullptr, nullptr))) {
        // SSL_CTX_add0_chain_cert vs. SSL_CTX_add_extra_chain_cert?
        if (SSL_CTX_add0_chain_cert(ctx, ca) != 1) {
            X509_free(ca);
            std::cerr << "Could not add certificate to chain" << std::endl;
            return 1;
        }
        // We must not delete the ca certs if they were successfully added to the chain.
        // We DO have to delete the main certificate though because SSL_CTX_use_certificate has
        // increased it reference count.
        // I am not sure how that makes sense (why not use SSL_CTX_add1_chain_cert and free either
        // way?). It seems to me using add0 might leak here?
    }
    const auto err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) != ERR_LIB_PEM || ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
        std::cerr << "Could not read chain" << std::endl;
        return 1;
    }
    X509_free(cert);
    BIO_free(chainBio);

    // Private Key
    // https://github.com/openssl/openssl/blob/8aaca20cf9996257d1ce2e6f4d3059b3698dde3d/ssl/ssl_rsa.c#L235
    auto keyBio = BIO_new_mem_buf(keyFileData.data(), keyFileData.size());
    assert(keyBio);
    auto key = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    assert(key);
    if (SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        std::cerr << "Could not load private key" << std::endl;
        return 1;
    }
    EVP_PKEY_free(key);
    BIO_free(keyBio);

    if (SSL_CTX_check_private_key(ctx) != 1) {
        std::cerr << "Certificate and private key do not match" << std::endl;
        return 1;
    }
    std::cout << "Load duration: "
              << (std::chrono::high_resolution_clock::now() - start).count() / 1000 << std::endl;
    return 0;
}
