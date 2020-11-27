#include "mctp_binding_fake.hpp"

struct FakeBindingBase
{
    virtual ~FakeBindingBase() = default;

    virtual mctp_binding_fake& fakeBinding() = 0;

    template <typename Data>
    std::tuple<mctp_pktbuf*, mctp_hdr*, Data*>
        prepareRequest(const mctp_eid_t src, const mctp_eid_t dest)
    {
        mctp_pktbuf* pkt = mctp_pktbuf_alloc(&fakeBinding().binding,
                                             sizeof(Data) + sizeof(mctp_hdr));

        auto hdr = mctp_pktbuf_hdr(pkt);
        hdr->dest = dest;
        hdr->src = src;
        hdr->ver = 1;
        hdr->flags_seq_tag =
            (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM | MCTP_HDR_FLAG_TO);

        memset(mctp_pktbuf_data(pkt), 0, sizeof(Data));

        return {pkt, hdr, reinterpret_cast<Data*>(mctp_pktbuf_data(pkt))};
    }

    template <typename Data>
    std::tuple<mctp_pktbuf*, mctp_hdr*, Data*>
        prepareCtrlRequest(const uint8_t command, const mctp_eid_t src,
                           const mctp_eid_t dest)
    {
        auto [pkt, hdr, request] = prepareRequest<Data>(src, dest);

        auto reqCtrlHdr = reinterpret_cast<mctp_ctrl_msg_hdr*>(request);
        reqCtrlHdr->command_code = command;
        reqCtrlHdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
        reqCtrlHdr->rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;

        return {pkt, hdr, reinterpret_cast<Data*>(mctp_pktbuf_data(pkt))};
    }

    template <typename Data>
    std::tuple<mctp_pktbuf*, mctp_hdr*, Data*>
        prepareResponse(const mctp_binding_fake::mctp_frame& request)
    {
        mctp_pktbuf* pkt = mctp_pktbuf_alloc(&fakeBinding().binding,
                                             sizeof(Data) + sizeof(mctp_hdr));

        auto hdr = mctp_pktbuf_hdr(pkt);
        hdr->dest = request.header.src;
        hdr->src = request.header.dest;
        hdr->ver = request.header.ver;
        hdr->flags_seq_tag = (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM);

        memset(mctp_pktbuf_data(pkt), 0, sizeof(Data));

        return {pkt, hdr, reinterpret_cast<Data*>(mctp_pktbuf_data(pkt))};
    }

    template <typename Data>
    std::tuple<mctp_pktbuf*, mctp_hdr*, Data*>
        prepareCtrlResponse(const mctp_binding_fake::mctp_frame& request)
    {
        auto [pkt, hdr, response] = prepareResponse<Data>(request);

        auto reqCtrlHdr =
            reinterpret_cast<const mctp_ctrl_msg_hdr*>(request.data.data());
        auto respCtrlHdr = reinterpret_cast<mctp_ctrl_msg_hdr*>(response);

        *respCtrlHdr = *reqCtrlHdr;
        respCtrlHdr->rq_dgram_inst &=
            static_cast<uint8_t>(~(MCTP_CTRL_HDR_FLAG_REQUEST));

        return {pkt, hdr, response};
    }

    void rx(mctp_pktbuf* pkt)
    {
        fakeBinding().rx(pkt);
    }

    template <typename T>
    void rx(mctp_pktbuf* pkt, const T& prv)
    {
        fakeBinding().rx(pkt, prv);
    }

    mctp_binding_fake::frame_log& log()
    {
        return fakeBinding().log;
    }
};