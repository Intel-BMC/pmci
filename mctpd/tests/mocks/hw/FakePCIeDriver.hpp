#pragma once

#include "hw/PCIeDriver.hpp"
#include "mctp_binding_fake.hpp"

struct FakePCIeDriver : public hw::PCIeDriver
{
    static constexpr uint8_t defaultMediumId = 0x0B; // PCIe3
    static constexpr uint16_t defaultBdf = 0xABBA;

    ~FakePCIeDriver() override = default;

    FakePCIeDriver(const size_t packet_size, const size_t prv_size) :
        hw(packet_size, prv_size)
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

    bool getBdf(uint16_t& bdf) override
    {
        bdf = defaultBdf;
        return true;
    }

    uint8_t getMediumId() override
    {
        return defaultMediumId;
    }

    bool setEndpointMap(std::vector<hw::EidInfo>&) override
    {
        return true;
    }

    mctp_binding_fake hw;
};