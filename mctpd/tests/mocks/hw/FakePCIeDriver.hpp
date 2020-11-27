#include "hw/PCIeDriver.hpp"
#include "mctp_binding_fake.hpp"

struct FakePCIeDriver : public hw::PCIeDriver
{
    FakePCIeDriver() = default;
    ~FakePCIeDriver() override = default;

    FakePCIeDriver(const size_t prv_size) : hw(prv_size)
    {
    }

    void init() override
    {
    }

    mctp_binding* binding() override
    {
        return &hw.binding;
    }

    void pollRx() override
    {
        // Nothing to do here, as RX will be driven by tests
    }

    bool registerAsDefault() override
    {
        return true;
    }

    bool getBdf(uint16_t&) override
    {
        // TODO: Mock?
        return true;
    }

    uint8_t getMediumId() override
    {
        return true;
    }

    bool setEndpointMap(std::vector<hw::EidInfo>&) override
    {
        return true;
    }

    mctp_binding_fake hw;
};