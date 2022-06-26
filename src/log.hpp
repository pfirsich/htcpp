#pragma once

#include <ostream>

namespace slog {
enum class Severity { Debug, Info, Warning, Error, Fatal };

void init(Severity severity = Severity::Info);
void setLogLevel(Severity severity);

namespace detail {
    // We use a custom string buf, so we can preallocate and clear to reuse the same buffer
    class StringStreamBuf : public std::streambuf {
    public:
        StringStreamBuf(size_t initialSize);

        std::streamsize xsputn(const char* s, std::streamsize n) override;

        void clear();
        std::string& string();

    private:
        std::string str_;
    };

    Severity& getCurrentLogLevel();

    void replaceDateTime(char* buffer, size_t size, const char* format);

    void log(std::string str);

    // This is thread-safe. Even though the whole program is single-threaded so far,
    // I don't want to have to worry about logging if I ever decide to make it multi-threaded.
    // EDIT: This decision turned out to be smart.
    template <typename... Args>
    void log(Severity severity, std::string_view severityStr, Args&&... args)
    {
        thread_local StringStreamBuf buf(1024);
        thread_local std::ostream os(&buf);
        buf.clear();
        if (static_cast<int>(severity) < static_cast<int>(getCurrentLogLevel())) {
            return;
        }
        static constexpr std::string_view dtDummy = "YYYY-mm-dd HH:MM:SS";
        (os << "[" << dtDummy << "] [" << severityStr << "] " << ... << args) << "\n";
        replaceDateTime(buf.string().data() + 1, dtDummy.size() + 1, "%F %T");
        //  Restore the char that was overwritten with null by strftime (so silly)
        buf.string().data()[1 + dtDummy.size()] = ']';
        log(buf.string());
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
