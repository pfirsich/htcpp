#pragma once

struct Stats {
    unsigned int connAccepted = 0;
    unsigned int connDropped = 0;
    unsigned int connActive = 0;

    // TODO: Maybe something to judge request sucess rate?
    // TODO: Some counters for SSL?
    // TODO: Total received/sent bytes? (on which layer?)

    // Some sort of averaged values would be cool, like req/s, though access log can help with this

    unsigned int recvError = 0;
    unsigned int sendError = 0;

    unsigned int reqReceived = 0;
    unsigned int reqError = 0;

    static Stats& get();
};
