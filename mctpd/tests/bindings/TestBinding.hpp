#pragma once

#include "MCTPBinding.hpp"
#include "utils/BindingBackdoor.hpp"

class TestBinding : public MctpBinding
{
    using PrvData = uint8_t;

  public:
    static constexpr mctp_eid_t eid = 8;
    static constexpr size_t packetSize = 4096;

    TestBinding(std::shared_ptr<object_server>& objServer,
                const std::string& objPath, Configuration& conf,
                boost::asio::io_context& ioc) :
        MctpBinding(objServer, objPath, conf, ioc,
                    mctp_server::BindingTypes::VendorDefined),
        driver(packetSize, sizeof(PrvData)), backdoor(driver)
    {
    }

    virtual ~TestBinding() = default;

    void initializeBinding() override
    {
        initializeMctp();

        struct mctp_binding* binding = &driver.binding;
        if (0 > mctp_register_bus(mctp, binding, eid))
        {
            throw std::runtime_error("mctp_register_bus failed");
        }
        mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                        static_cast<MctpBinding*>(this));
        mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                         static_cast<MctpBinding*>(this));
        mctp_binding_set_tx_enabled(binding, true);
    }

    mctp_binding_fake driver;
    BindingBackdoor<PrvData> backdoor;

    /** Extract protected functions externally */
    using MctpBinding::getEidCtrlCmd;
};
