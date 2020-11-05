#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <unordered_set>

static std::shared_ptr<sdbusplus::asio::connection> conn;

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string mctpTypeName =
    "xyz.openbmc_project.Configuration.MctpConfiguration";

static std::unordered_set<std::string> startedUnits;

static std::vector<std::string> getConfigurationPaths()
{
    auto method_call = conn->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

    method_call.append("/xyz/openbmc_project/inventory/system/board", 2,
                       std::array<std::string, 1>({mctpTypeName}));

    auto reply = conn->call(method_call);
    std::vector<std::string> paths;
    reply.read(paths);
    return paths;
}

static void startUnit(const std::string& objectPath)
{
    const auto serviceArgument = boost::algorithm::replace_all_copy(
        boost::algorithm::replace_first_copy(
            objectPath, "/xyz/openbmc_project/inventory/system/board/", ""),
        "/", "_2f");
    const auto unitName =
        "xyz.openbmc_project.mctpd@" + serviceArgument + ".service";

    try
    {
        auto method_call = conn->new_method_call(
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager", "StartUnit");
        method_call.append(unitName, "replace");
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Starting unit " + unitName).c_str());
        conn->call(method_call);
        startedUnits.emplace(objectPath);
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Started unit " + unitName).c_str());
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Error starting unit " + unitName).c_str());
    }
}

static void startExistingConfigurations()
{
    std::vector<std::string> configurationPaths;
    try
    {
        configurationPaths = getConfigurationPaths();
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Could not retrieve existing configurations: ") +
             e.what())
                .c_str());
        return;
    }

    for (const auto& objectPath : configurationPaths)
    {
        if (startedUnits.count(objectPath) != 0)
        {
            continue;
        }
        try
        {
            startUnit(objectPath);
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("Could not start existing configuration at path " +
                 objectPath + ": " + e.what())
                    .c_str());
        }
    }
}

int main()
{
    boost::asio::io_context ioc;
    conn = std::make_shared<sdbusplus::asio::connection>(ioc);

    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    conn->request_name("xyz.openbmc_project.PMCI_Launcher");

    startExistingConfigurations();

    boost::asio::steady_timer timer(ioc);
    std::vector<std::string> units;
    namespace rules = sdbusplus::bus::match::rules;

    auto match = std::make_unique<sdbusplus::bus::match::match>(
        *conn,
        rules::interfacesAdded() + rules::path_namespace("/") +
            rules::sender("xyz.openbmc_project.EntityManager"),
        [&timer, &units](sdbusplus::message::message& message) {
            if (message.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Callback method error");
                return;
            }
            sdbusplus::message::object_path unitPath;
            std::unordered_map<std::string, ConfigurationMap> interfacesAdded;
            try
            {
                message.read(unitPath, interfacesAdded);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Message read error");
                return;
            }

            if (startedUnits.count(unitPath) != 0)
            {
                return;
            }
            for (const auto& interface : interfacesAdded)
            {
                if (interface.first != mctpTypeName)
                {
                    continue;
                }

                // Note: Interfaces may take a while to be visible.
                // Let's wait a moment, otherwise mctpd might get UnknownObject
                units.emplace_back(unitPath);
                timer.expires_after(std::chrono::seconds(1));
                timer.async_wait([&units](const boost::system::error_code& ec) {
                    if (ec == boost::asio::error::operation_aborted)
                    {
                        return;
                    }
                    if (ec)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Timer error");
                        return;
                    }
                    for (const auto& unit : units)
                    {
                        startUnit(unit);
                    }
                    units.clear();
                });
            }
        });

    // Install signal handler so destructors are called upon finalization
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](const boost::system::error_code&, const int&) {
        // Stop processing events
        ioc.stop();
    });

    // Process events until stop is called
    ioc.run();
    return 0;
}
