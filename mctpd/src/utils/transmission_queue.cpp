#include "utils/transmission_queue.hpp"

#include <phosphor-logging/log.hpp>

using mctpd::MctpTransmissionQueue;

MctpTransmissionQueue::Message::Message(size_t index_,
                                        std::vector<uint8_t>&& payload_,
                                        std::vector<uint8_t>&& privateData_,
                                        boost::asio::io_context& ioc) :
    index(index_),
    payload(std::move(payload_)), privateData(std::move(privateData_)),
    timer(ioc)
{
}

std::optional<uint8_t> MctpTransmissionQueue::Tags::next() const
{
    if (!bits)
    {
        return std::nullopt;
    }
    return static_cast<uint8_t>(__builtin_ctz(bits));
}

void MctpTransmissionQueue::Tags::emplace(uint8_t flag)
{
    bits |= static_cast<uint8_t>(1 << flag);
}

void MctpTransmissionQueue::Tags::erase(uint8_t flag)
{
    bits &= static_cast<uint8_t>(~(1 << flag));
}

std::shared_ptr<MctpTransmissionQueue::Message> MctpTransmissionQueue::transmit(
    struct mctp* mctp, mctp_eid_t destEid, std::vector<uint8_t>&& payload,
    std::vector<uint8_t>&& privateData, boost::asio::io_context& ioc)
{
    auto& endpoint = endpoints[destEid];
    auto msgIndex = endpoint.msgCounter++;
    auto message = std::make_shared<Message>(msgIndex, std::move(payload),
                                             std::move(privateData), ioc);
    endpoint.queuedMessages.emplace(msgIndex, message);
    endpoint.transmitQueuedMessages(mctp, destEid);
    return message;
}

void MctpTransmissionQueue::Endpoint::transmitQueuedMessages(struct mctp* mctp,
                                                             mctp_eid_t destEid)
{
    while (!queuedMessages.empty())
    {
        const std::optional<uint8_t> nextTag = availableTags.next();
        if (!nextTag)
        {
            break;
        }
        auto msgTag = nextTag.value();
        auto queuedMessageIter = queuedMessages.begin();
        auto message = std::move(queuedMessageIter->second);
        queuedMessages.erase(queuedMessageIter);

        int rc = mctp_message_tx(mctp, destEid, message->payload.data(),
                                 message->payload.size(), true, msgTag,
                                 message->privateData.data());
        if (rc < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error in mctp_message_tx");
            continue;
        }

        availableTags.erase(msgTag);
        message->tag = msgTag;
        transmittedMessages.emplace(msgTag, std::move(message));
    }
}

bool MctpTransmissionQueue::receive(struct mctp* mctp, mctp_eid_t srcEid,
                                    uint8_t msgTag,
                                    std::vector<uint8_t>&& response,
                                    boost::asio::io_context& ioc)
{
    auto endpointIter = endpoints.find(srcEid);
    if (endpointIter == endpoints.end())
    {
        return false;
    }

    auto& endpoint = endpointIter->second;
    auto messageIter = endpoint.transmittedMessages.find(msgTag);
    if (messageIter == endpoint.transmittedMessages.end())
    {
        return false;
    }

    const auto message = messageIter->second;
    message->response = std::move(response);
    endpoint.transmittedMessages.erase(messageIter);
    message->tag.reset();
    endpoint.availableTags.emplace(msgTag);

    // Now that another tag is available, try to transmit any queued messages
    message->timer.cancel();
    ioc.post([this, mctp, srcEid] {
        endpoints[srcEid].transmitQueuedMessages(mctp, srcEid);
    });
    return true;
}

void MctpTransmissionQueue::dispose(mctp_eid_t destEid,
                                    const std::shared_ptr<Message>& message)
{
    auto& endpoint = endpoints[destEid];
    auto queuedMessageIter = endpoint.queuedMessages.find(message->index);
    if (queuedMessageIter != endpoint.queuedMessages.end())
    {
        endpoint.queuedMessages.erase(queuedMessageIter);
    }
    if (message->tag)
    {
        auto msgTag = message->tag.value();
        endpoint.availableTags.emplace(msgTag);

        auto transmittedMessageIter = endpoint.transmittedMessages.find(msgTag);
        if (transmittedMessageIter != endpoint.transmittedMessages.end())
        {
            endpoint.transmittedMessages.erase(transmittedMessageIter);
        }
    }
}