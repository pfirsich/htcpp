#pragma once

#include <ctime>
#include <iostream>
#include <thread>

#include <unistd.h>

#include "ioqueue.hpp"

namespace rlog {
enum class Severity { Debug, Info, Warning, Error, Fatal };

void setLogLevel(Severity severity);

namespace detail {
    // We use a streambuf, so we don't have to worry about formatting and can simply use all the
    // operator<<s
    class AsyncStreamBuf : public std::streambuf {
    public:
        AsyncStreamBuf();

        std::streamsize xsputn(const char* s, std::streamsize n) override;

    private:
        void threadFunc();

        // We can't use IoQueue here, because it's not thread-safe
        IoURing ring_;
        std::thread thread_;
    };

    Severity& getCurrentLogLevel();

    std::string getDateTimeStr();

    template <typename... Args>
    void log(Severity severity, std::string_view severityStr, Args&&... args)
    {
        static AsyncStreamBuf sb;
        static std::ostream os(&sb);
        if (static_cast<int>(severity) < static_cast<int>(getCurrentLogLevel())) {
            return;
        }
        (os << "[" << detail::getDateTimeStr() << "]"
            << " [" << severityStr << "] " << ... << args)
            << "\n";
    }
}

template <typename... Args>
void debug(Args&&... args)
{
    detail::log(Severity::Debug, "DEBUG", std::forward<Args>(args)...);
}

template <typename... Args>
void info(Args&&... args)
{
    detail::log(Severity::Info, "INFO", std::forward<Args>(args)...);
}

template <typename... Args>
void warning(Args&&... args)
{
    detail::log(Severity::Warning, "WARNING", std::forward<Args>(args)...);
}

template <typename... Args>
void error(Args&&... args)
{
    detail::log(Severity::Error, "ERROR", std::forward<Args>(args)...);
}

template <typename... Args>
void fatal(Args&&... args)
{
    detail::log(Severity::Fatal, "FATAL", std::forward<Args>(args)...);
}
}
