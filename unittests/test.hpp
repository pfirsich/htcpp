#include <functional>
#include <iostream>
#include <string>
#include <vector>

static constexpr const char* ESC_RESET = "\x1b[0m";
static constexpr const char* ESC_BOLD = "\x1b[1m";
constexpr const char* ESC_GREEN = "\x1b[32m";
constexpr const char* ESC_RED = "\x1b[31m";

namespace detail {
struct TestCase {
    struct Context {
        bool testPassed = true;

        void check(bool cond, std::string condStr)
        {
            if (!cond) {
                if (testPassed) {
                    std::cerr << ESC_RED << "FAIL" << ESC_RESET << "\n";
                }
                testPassed = false;
                std::cerr << "'" << condStr << "' failed.\n";
            }
        }
    };

    std::string name;
    std::string file;
    int line;
    std::function<void(Context&)> func;

    TestCase(std::string name, std::string file, int line, std::function<void(Context&)> func)
        : name(std::move(name))
        , file(std::move(file))
        , line(line)
        , func(std::move(func))
    {
        registry.push_back(this);
    }

    static std::vector<TestCase*> registry;
};
}

#define TEST_CAT(s1, s2) s1##s2
// This extra layer of indirection (via INNER) is needed so __COUNTER__ gets expanded properly.
// I don't even care why that is necessary, but it hurt to figure out.
#define TEST_FUNCNAME_INNER(counter) TEST_CAT(TEST_FUNCNAME_PREFIX_, counter)
#define TEST_FUNCNAME(counter) TEST_FUNCNAME_INNER(counter)
#define TEST_TC_NAME(func_name) func_name##_tc

#define TEST_CREATE_TEST_CASE(func_name, tc_name)                                                  \
    static void func_name(detail::TestCase::Context&);                                             \
    static const detail::TestCase TEST_TC_NAME(func_name)(tc_name, __FILE__, __LINE__, func_name); \
    static void func_name([[maybe_unused]] detail::TestCase::Context& testContext)

#define TEST_CASE(tc_name) TEST_CREATE_TEST_CASE(TEST_FUNCNAME(__COUNTER__), tc_name)

#define TEST_CHECK(cond) testContext.check(cond, #cond);
#define TEST_REQUIRE(cond)                                                                         \
    testContext.check(cond, #cond);                                                                \
    return;

#ifdef TEST_DEFINE_MAIN
std::vector<detail::TestCase*> detail::TestCase::registry;

int main()
{
    for (size_t i = 0; i < detail::TestCase::registry.size(); ++i) {
        const auto tc = detail::TestCase::registry[i];
        detail::TestCase::Context ctx;
        std::cerr << ESC_BOLD << "[" << i + 1 << "/" << detail::TestCase::registry.size() << "] "
                  << tc->name << ":" << ESC_RESET << " ";
        tc->func(ctx);
        if (ctx.testPassed) {
            std::cerr << ESC_GREEN << "PASS" << ESC_RESET << "\n";
        }
    }
}
#endif
