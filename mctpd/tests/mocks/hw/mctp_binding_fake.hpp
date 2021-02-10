#pragma once

#include <functional>
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
        std::vector<uint8_t> payload;
        std::vector<uint8_t> privateData;

        template <typename Payload>
        struct interpreted
        {
            const mctp_hdr* hdr;
            const Payload* payload;
        };

        template <typename Payload, typename PrivateData>
        struct interpreted_ext
        {
            const mctp_hdr* hdr;
            const Payload* payload;
            const PrivateData* prv;
        };

        template <typename Payload>
        interpreted<Payload> unpack(const size_t padding = 0) const
        {
            if (sizeof(Payload) != payload.size() + padding)
            {
                throw std::runtime_error("Invalid buffer size");
            }
            return {&header, reinterpret_cast<const Payload*>(payload.data())};
        }

        template <typename Payload, typename PrivateData>
        interpreted_ext<Payload, PrivateData>
            unpack(const size_t padding = 0) const
        {
            if (sizeof(Payload) != payload.size() + padding)
            {
                throw std::runtime_error("Invalid buffer size");
            }

            if (sizeof(PrivateData) != privateData.size())
            {
                throw std::runtime_error("Invalid private buffer size");
            }

            return {&header, reinterpret_cast<const Payload*>(payload.data()),
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

    class frame_matchers
    {
      public:
        using predicate = std::function<bool(const mctp_frame&)>;
        using handler = std::function<void()>;

        void match(predicate&& when, handler&& handle)
        {
            matchers.emplace_back(
                std::make_pair(std::move(when), std::move(handle)));
        }

        void check(const mctp_frame& frame)
        {
            auto it = matchers.begin();
            while (it != matchers.end())
            {
                if (it->first(frame))
                {
                    // Extract element from the list before calling callback, as
                    // condition was met
                    auto pair = std::move(*it);
                    matchers.erase(it);

                    // Call handler from current (moved) variable
                    pair.second();

                    // Start from the beginning, as list could have changed
                    // during callback
                    it = matchers.begin();
                }
                else
                {
                    ++it;
                }
            }
        }

      private:
        std::list<std::pair<predicate, handler>> matchers;
    };

    mctp_binding binding{};
    frame_log log;
    frame_matchers matchers;

    mctp_binding_fake(const size_t packet_size, const size_t prv_size)
    {
        binding.name = "fake";
        binding.version = 1;

        binding.tx = tx;
        binding.pkt_size = MCTP_PACKET_SIZE(packet_size);

        binding.pkt_pad = 0;
        binding.pkt_priv_size = prv_size;
    }

    static int tx(struct mctp_binding* binding, struct mctp_pktbuf* pkt)
    {
        auto driver = container_of(binding, mctp_binding_fake, binding);
        driver->log.tx.push_back(toMctpFrame(binding, pkt));
        driver->matchers.check(driver->log.tx.back());
        return 0;
    }

    void rx(struct mctp_pktbuf* pkt)
    {
        log.rx.push_back(toMctpFrame(&binding, pkt));
        mctp_bus_rx(&binding, pkt);
    }

    static mctp_frame toMctpFrame(mctp_binding* binding, mctp_pktbuf* pkt)
    {
        mctp_hdr* hdr = mctp_pktbuf_hdr(pkt);
        size_t dataLen = (pkt->end - pkt->start) -
                         sizeof(*hdr); // TODO: bring back mctp_pktbuf_size()
                                       // when it will be fixed
        auto pData = reinterpret_cast<uint8_t*>(mctp_pktbuf_data(pkt));
        auto pPrivData = reinterpret_cast<uint8_t*>(pkt->msg_binding_private);
        // TODO: Reimplement class when multi-packet messages are needed
        std::vector<uint8_t> data(pData, pData + dataLen);
        std::vector<uint8_t> privateData(pPrivData,
                                         pPrivData + binding->pkt_priv_size);

        return {*hdr, data, privateData};
    }
};
