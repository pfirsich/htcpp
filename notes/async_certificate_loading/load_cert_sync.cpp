#include <cassert>
#include <chrono>
#include <iostream>

#include <openssl/ssl.h>

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "Usage: load_cert_sync <certfile> <privkeyfile>" << std::endl;
        return 1;
    }

    SSL_CTX* ctx_ = SSL_CTX_new(TLS_server_method());
    assert(ctx_);
    const auto start = std::chrono::high_resolution_clock::now();
    if (SSL_CTX_use_certificate_chain_file(ctx_, argv[1]) != 1) {
        std::cerr << "Could not load certificate" << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx_, argv[2], SSL_FILETYPE_PEM) != 1) {
        std::cerr << "Could not load private key file" << std::endl;
        return false;
    }

    if (SSL_CTX_check_private_key(ctx_) != 1) {
        std::cerr << "Certificate and private key do not match" << std::endl;
        return false;
    }
    std::cout << "Duration: " << (std::chrono::high_resolution_clock::now() - start).count() / 1000
              << std::endl;
    return true;
}
