#include "log.hpp"

namespace rlog {
void setLogLevel(Severity severity)
{
    detail::getCurrentLogLevel() = severity;
}

detail::AsyncStreamBuf::AsyncStreamBuf()
{
    ring_.init(4096);
    thread_ = std::thread([this]() { threadFunc(); });
}

void detail::AsyncStreamBuf::threadFunc()
{
    while (true) {
        const auto cqe = ring_.waitCqe();
        if (!cqe) {
            // I don't know why that happens, but sometimes it does
            continue;
        }
        auto buffer = reinterpret_cast<std::string*>(cqe->user_data);
        delete buffer;
        ring_.advanceCq();
    }
}

std::streamsize detail::AsyncStreamBuf::xsputn(const char* s, std::streamsize n)
{
    auto buffer = new std::string(s, n);
    const auto sqe = ring_.prepareWrite(STDOUT_FILENO, buffer->data(), buffer->size());
    sqe->user_data = reinterpret_cast<unsigned long long>(buffer);
    // The completion order of SQE is not the submission order. So in order to have our log lines
    // not all mixed up, we have to instruct io_uring to wait with starting the write
    // until all previously submitted SQEs have completed.
    sqe->flags |= IOSQE_IO_DRAIN;
    ring_.submitSqes();
    return buffer->size();
}

Severity& detail::getCurrentLogLevel()
{
    static Severity severity = Severity::Info;
    return severity;
}

std::string detail::getDateTimeStr()
{
    const auto t = std::time(nullptr);
    char buf[32];
    const auto n = std::strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
    assert(n > 0);
    return std::string(buf, n);
}
}
