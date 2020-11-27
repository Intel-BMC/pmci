#include <boost/asio/io_context.hpp>
#include <chrono>
#include <future>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

struct AsyncTestBase : ::testing::Test
{
    constexpr static auto executionTimeout = std::chrono::milliseconds{500};

    class timeout_occurred : public std::runtime_error
    {
      public:
        timeout_occurred(const std::string& what) : std::runtime_error(what)
        {
        }
    };

    template <typename Result>
    static auto makePromise()
    {
        struct AsyncPair
        {
            std::promise<Result> promise;
            std::future<Result> future{promise.get_future()};
        } asyncPair;
        return asyncPair;
    }

    // Specialization for coroutines
    template <typename Functor>
    std::enable_if_t<
        std::is_invocable<Functor, boost::asio::yield_context>::value>
        schedule(Functor& func)
    {
        boost::asio::spawn(ioc, func);
    }

    // Specialization for 'normal' invocables
    template <typename Functor>
    std::enable_if_t<
        !std::is_invocable<Functor, boost::asio::yield_context>::value>
        schedule(Functor& func)
    {
        boost::asio::post(ioc, func);
    }

    template <typename... Functors>
    void schedule(Functors&... funcs)
    {
        (schedule(funcs), ...);
    }

    template <typename Future>
    static bool ready(Future& future)
    {
        return future.valid() && std::future_status::ready ==
                                     future.wait_for(std::chrono::seconds{0});
    }

    template <typename... Futures>
    static bool ready(Futures&... futures)
    {
        std::vector<bool> statuses{ready(futures)...};
        return std::all_of(statuses.begin(), statuses.end(),
                           [](bool complete) { return complete == true; });
    }

    template <typename... Futures>
    bool waitAll(std::chrono::milliseconds timeout, Futures&... futures)
    {
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
        const auto deadline = now + timeout;

        do
        {
            ioc.poll();
            if (ready(futures...))
            {
                return true;
            }

            now = std::chrono::high_resolution_clock::now().time_since_epoch();
        } while (deadline > now);

        throw timeout_occurred(
            "Timeout while waiting for promise to be fulfiled");
    }

    template <typename... Futures>
    bool waitAll(Futures&... futures)
    {
        return waitAll(executionTimeout, futures...);
    }

    template <typename Result>
    Result waitFor(std::chrono::milliseconds timeout,
                   std::future<Result>& future)
    {
        waitAll(timeout, future);
        return future.get();
    }

    template <typename Result>
    Result waitFor(std::future<Result>& future)
    {
        return waitFor(executionTimeout, future);
    }

    boost::asio::io_context ioc;
};
