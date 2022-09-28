#pragma once

#include <thread>

#include "client.hpp"
#include "config.hpp"
#include "events.hpp"
#include "result.hpp"
#include "ssl.hpp"

class AcmeClient {
public:
    struct Challenge {
        std::string path;
        std::string content;
    };

    AcmeClient(IoQueue& io, Config::Acme config);

    std::shared_ptr<SslContext> getCurrentContext() const;
    std::shared_ptr<std::vector<Challenge>> getChallenges() const;

private:
    void threadFunc();
    bool needIssueCertificate() const;
    bool updateContext();
    bool issueCertificate(
        const std::string& jwk, const std::string& jwkThumbprint, EVP_PKEY* accountPkey);

    IoQueue& io_;
    Config::Acme config_;
    ThreadRequester requester_;
    std::shared_ptr<std::vector<Challenge>> challenges_;
    // These listeners are sent events from the threadFunc and simply set the corresponding member
    // variables from the main thread
    EventListener<decltype(challenges_)> challengesListener_;
    std::shared_ptr<SslContext> currentContext_;
    EventListener<decltype(currentContext_)> currentContextListener_;
    std::thread thread_;
};

// The host handlers have to get these by name somehow, so this is how it is.
// I have been working on this feature for weeks and I don't want to think too much about how to do
// this properly, so I just do this silly shit.
AcmeClient* registerAcmeClient(const std::string& name, IoQueue& io, Config::Acme config);
AcmeClient* getAcmeClient(const std::string& name);

struct AcmeSslConnectionFactory {
    using Connection = SslConnection;

    AcmeClient* acmeClient;

    std::unique_ptr<Connection> create(IoQueue& io, int fd)
    {
        auto context = acmeClient->getCurrentContext();
        return context ? std::make_unique<Connection>(io, fd, std::move(context)) : nullptr;
    }
};
