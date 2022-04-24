#include "config.hpp"
#include "ioqueue.hpp"
#include "log.hpp"
#include "server.hpp"

int main()
{
    std::cout << "Starting HTTP server.." << std::endl;
    const auto& config = Config::get();
    std::cout << "listenPort: " << config.listenPort << std::endl;
    std::cout << "listenBacklog: " << config.listenBacklog << std::endl;
    std::cout << "ioQueueSize: " << config.ioQueueSize << std::endl;
    std::cout << "readAmount: " << config.readAmount << std::endl;
    std::cout << "singleReadTimeoutMs: " << config.singleReadTimeoutMs << std::endl;
    std::cout << "fullReadTimeoutMs: " << config.fullReadTimeoutMs << std::endl;
    std::cout << "maxUrlLength: " << config.maxUrlLength << std::endl;
    std::cout << "maxRequestSize: " << config.maxRequestSize << std::endl;
    std::cout << "defaultRequestSize: " << config.defaultRequestSize << std::endl;

    rlog::setLogLevel(rlog::Severity::Debug);

    IoQueue io(config.ioQueueSize);

    Server<TcpConnection> server(io);
    server.start();

    return 0;
}
