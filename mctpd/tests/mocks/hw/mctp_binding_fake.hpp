#pragma once

#include <list>
#include <vector>

#include "libmctp.h"

#ifndef container_of
#define container_of(ptr, type, member)                                        \
    reinterpret_cast<type*>(                                                   \
        reinterpret_cast<char*>(ptr) -                                         \
        reinterpret_cast<char*>(&(reinterpret_cast<type*>(0))->member))
#endif

struct mctp_binding_fake
{
    struct mctp_frame
    {
        mctp_hdr header;
        std::vector<uint8_t> data;
        std::vector<uint8_t> privateData;

        template <typename Data>
        std::tuple<const mctp_hdr*, const Data*> unpack() const
        {
            if (sizeof(Data) != data.size())
            {
                throw std::runtime_error("Invalid buffer size");
            }
            return {&header, reinterpret_cast<const Data*>(data.data())};
        }

        template <typename Data, typename PrivateData>
        std::tuple<const mctp_hdr*, const Data*, const PrivateData*>
            unpack() const
        {
            if (sizeof(Data) != data.size())
            {
                throw std::runtime_error("Invalid buffer size");
            }

            if (sizeof(PrivateData) != privateData.size())
            {
                throw std::runtime_error("Invalid private buffer size");
            }

            return {&header, reinterpret_cast<const Data*>(data.data()),
                    reinterpret_cast<const PrivateData*>(privateData.data())};
        }
    };

    struct frame_log
    {
        std::list<mctp_frame> tx;
        std::list<mctp_frame> rx;

        const mctp_frame& lastTx()
        {
            if (tx.size() == 0)
            {
                throw std::runtime_error("TX empty");
            }

            return tx.back();
        }

        const mctp_frame& lastRx()
        {
            if (rx.size() == 0)
            {
                throw std::runtime_error("RX empty");
            }

            return rx.back();
        }
    };

    mctp_binding binding{};
    frame_log log;

    mctp_binding_fake(const size_t prv_size = 0)
    {
        binding.name = "fake";
        binding.version = 1;

        binding.tx = tx;
        binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);

        binding.pkt_pad = 0;
        binding.pkt_priv_size = prv_size;
    }

    static int tx(struct mctp_binding* binding, struct mctp_pktbuf* pkt)
    {
        auto driver = container_of(binding, mctp_binding_fake, binding);
        driver->log.tx.push_back(toMctpFrame(binding, pkt));
        return 0;
    }

    void rx(struct mctp_pktbuf* pkt)
    {
        if (binding.pkt_priv_size != 0)
        {
            throw std::runtime_error("RX: Private data not provided");
        }

        log.rx.push_back(toMctpFrame(&binding, pkt));
        mctp_bus_rx(&binding, pkt);
    }

    template <typename T>
    void rx(struct mctp_pktbuf* pkt, const T& prv)
    {
        if (binding.pkt_priv_size != sizeof(T))
        {
            throw std::runtime_error("RX: Invalid prv size");
        }

        *reinterpret_cast<T*>(pkt->msg_binding_private) = prv;

        log.rx.push_back(toMctpFrame(&binding, pkt));
        mctp_bus_rx(&binding, pkt);
    }

    static mctp_frame toMctpFrame(mctp_binding* binding, mctp_pktbuf* pkt)
    {
        mctp_hdr* hdr = mctp_pktbuf_hdr(pkt);
        size_t dataLen = mctp_pktbuf_size(pkt) - sizeof(*hdr);
        auto pData = reinterpret_cast<uint8_t*>(mctp_pktbuf_data(pkt));
        std::vector<uint8_t> data(pData, pData + dataLen);
        auto pPrivData = reinterpret_cast<uint8_t*>(pkt->msg_binding_private);
        std::vector<uint8_t> privateData(pPrivData,
                                         pPrivData + binding->pkt_priv_size);

        return {*hdr, data, privateData};
    }
};
