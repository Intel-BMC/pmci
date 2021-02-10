#pragma once

#include "mocks/hw/mctp_binding_fake.hpp"

template <typename PrvData>
class BindingBackdoor
{
  public:
    template <typename Payload>
    struct BindingIO
    {
        mctp_pktbuf* pkt;
        mctp_hdr* hdr;
        Payload* payload;
        PrvData* prv;
    };

    struct Route
    {
        const mctp_eid_t src;
        const mctp_eid_t dest;
    };

    BindingBackdoor(mctp_binding_fake& fakeBindingArg) :
        fakeBinding(fakeBindingArg)
    {
    }

    template <typename Payload>
    void validateSize(const size_t padding)
    {
        // TODO: Reimplement class when multi-packet messages are needed
        const size_t PACKET_SIZE = sizeof(Payload) + sizeof(mctp_hdr) + padding;
        if (PACKET_SIZE > fakeBinding.binding.pkt_size)
        {
            throw std::runtime_error(
                "Requested packet size is too big to handle in single message");
        }
    }

    template <typename Payload>
    BindingIO<Payload> prepareRequest(Route route, const PrvData& prvData = {},
                                      const size_t padding = 0)
    {
        validateSize<Payload>(padding);

        mctp_pktbuf* pkt = mctp_pktbuf_alloc(
            &fakeBinding.binding, sizeof(Payload) + sizeof(mctp_hdr) + padding);

        auto hdr = mctp_pktbuf_hdr(pkt);
        hdr->dest = route.dest;
        hdr->src = route.src;
        hdr->ver = 1;
        hdr->flags_seq_tag =
            (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM | MCTP_HDR_FLAG_TO);

        memset(mctp_pktbuf_data(pkt), 0, sizeof(Payload) + padding);

        *reinterpret_cast<PrvData*>(pkt->msg_binding_private) = prvData;

        return BindingIO<Payload>{
            pkt, hdr, reinterpret_cast<Payload*>(mctp_pktbuf_data(pkt)),
            reinterpret_cast<PrvData*>(pkt->msg_binding_private)};
    }

    template <typename Payload>
    BindingIO<Payload> prepareCtrlRequest(const uint8_t command, Route route,
                                          const PrvData& prvData = {},
                                          const size_t padding = 0)
    {
        auto io = prepareRequest<Payload>(route, prvData, padding);

        auto reqCtrlHdr = reinterpret_cast<mctp_ctrl_msg_hdr*>(io.payload);
        reqCtrlHdr->command_code = command;
        reqCtrlHdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
        reqCtrlHdr->rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;

        return io;
    }

    template <typename Payload>
    BindingIO<Payload>
        prepareResponse(const mctp_binding_fake::mctp_frame& request,
                        const PrvData& prvData = {}, const size_t padding = 0)
    {
        validateSize<Payload>(padding);

        mctp_pktbuf* pkt = mctp_pktbuf_alloc(
            &fakeBinding.binding, sizeof(Payload) + sizeof(mctp_hdr) + padding);

        auto hdr = mctp_pktbuf_hdr(pkt);
        hdr->dest = request.header.src;
        hdr->src = request.header.dest;
        hdr->ver = request.header.ver;
        hdr->flags_seq_tag = (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM);

        memset(mctp_pktbuf_data(pkt), 0, sizeof(Payload) + padding);

        *reinterpret_cast<PrvData*>(pkt->msg_binding_private) = prvData;

        return BindingIO<Payload>{
            pkt, hdr, reinterpret_cast<Payload*>(mctp_pktbuf_data(pkt)),
            reinterpret_cast<PrvData*>(pkt->msg_binding_private)};
    }

    template <typename Payload>
    BindingIO<Payload>
        prepareCtrlResponse(const mctp_binding_fake::mctp_frame& request,
                            const PrvData& prvData = {},
                            const size_t padding = 0)
    {
        auto io = prepareResponse<Payload>(request, prvData, padding);

        auto reqCtrlHdr =
            reinterpret_cast<const mctp_ctrl_msg_hdr*>(request.payload.data());
        auto respCtrlHdr = reinterpret_cast<mctp_ctrl_msg_hdr*>(io.payload);

        *respCtrlHdr = *reqCtrlHdr;
        respCtrlHdr->rq_dgram_inst &=
            static_cast<uint8_t>(~(MCTP_CTRL_HDR_FLAG_REQUEST));

        return io;
    }

    template <typename Payload>
    BindingIO<Payload> prepareResponse(const PrvData& prvData = {},
                                       const size_t padding = 0)
    {
        return prepareResponse<Payload>(log().lastTx(), prvData, padding);
    }

    template <typename Payload>
    BindingIO<Payload> prepareCtrlResponse(const PrvData& prvData = {},
                                           const size_t padding = 0)
    {
        return prepareCtrlResponse<Payload>(log().lastTx(), prvData, padding);
    }

    template <typename Payload>
    BindingIO<Payload> lastOutgoingMessage(const size_t padding = 0)
    {
        auto frame = log().lastTx().template unpack<Payload, PrvData>(padding);
        return BindingIO<Payload>{nullptr, const_cast<mctp_hdr*>(frame.hdr),
                                  const_cast<Payload*>(frame.payload),
                                  const_cast<PrvData*>(frame.prv)};
    }

    template <typename Payload>
    void rx(BindingIO<Payload>& io)
    {
        fakeBinding.rx(io.pkt);
    }

    mctp_binding_fake::frame_log& log()
    {
        return fakeBinding.log;
    }

  private:
    mctp_binding_fake& fakeBinding;
};