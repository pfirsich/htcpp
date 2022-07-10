#include "log.hpp"

#include <cassert>
#include <ctime>
#include <thread>

#include <unistd.h>

#include "mpscqueue.hpp"

namespace slog {
namespace {
    MpscQueue<std::string>& logQueue()
    {
        static MpscQueue<std::string> queue;
        return queue;
    }

    std::atomic<bool>& logThreadRunning()
    {
        static std::atomic<bool> running;
        return running;
    }

    std::thread& logThread()
    {
        static std::thread t;
        return t;
    }

    void logThreadFunc()
    {
        auto& queue = logQueue();
        auto& running = logThreadRunning();
        while (true) {
            const auto line = queue.consume();
            if (!line) {
                if (!running.load()) {
                    return;
                }
                ::usleep(1);
                continue;
            }
            [[maybe_unused]] auto ignore = ::write(STDOUT_FILENO, line->data(), line->size());
        }
    }

    void logAtExit()
    {
        logThreadRunning().store(false);
        logThread().join();
    }
}

std::string_view toString(Severity severity)
{
    static constexpr std::array strings { "DEBUG", "INFO", "WARNING", "ERROR", "FATAL" };
    const auto idx = static_cast<int>(severity);
    if (idx < 0 || static_cast<size_t>(idx) >= strings.size()) {
        return "INVALID";
    }
    return strings[idx];
}

void setLogLevel(Severity severity)
{
    detail::getCurrentLogLevel() = severity;
}

void init(Severity severity)
{
    // Check that thread is default-constructed (not running yet)
    assert(logThread().get_id() == std::thread::id());
    setLogLevel(severity);
    logThreadRunning().store(true);
    logThread() = std::thread { logThreadFunc };
    // Maybe I also need to think of something for abnormal termination
    std::atexit(logAtExit);
}

namespace detail {
    StringStreamBuf::StringStreamBuf(size_t initialSize)
        : str_(initialSize, 0)
    {
        str_.resize(0);
    }

    std::streamsize StringStreamBuf::xsputn(const char* s, std::streamsize n)
    {
        str_.append(s, n);
        return n;
    }

    void StringStreamBuf::clear()
    {
        str_.clear();
    }

    std::string& StringStreamBuf::string()
    {
        return str_;
    }

    Severity& getCurrentLogLevel()
    {
        static Severity severity = Severity::Info;
        return severity;
    }

    void replaceDateTime(char* buffer, size_t size, const char* format)
    {
        const auto t = std::time(nullptr);
        [[maybe_unused]] const auto n = std::strftime(buffer, size, format, std::localtime(&t));
        assert(n > 0);
    }

    void log(std::string str)
    {
        logQueue().produce(std::move(str));
    }
}
}
