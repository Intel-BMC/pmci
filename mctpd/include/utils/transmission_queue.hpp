/*
// Copyright (c) 2021 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include <libmctp.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <map>
#include <optional>
#include <vector>

namespace mctpd
{

class MctpTransmissionQueue
{
  public:
    struct Message
    {
        Message(size_t index_, std::vector<uint8_t>&& payload_,
                std::vector<uint8_t>&& privateData_,
                boost::asio::io_context& ioc);

        size_t index{0};
        std::optional<uint8_t> tag;
        std::vector<uint8_t> payload{};
        std::vector<uint8_t> privateData{};
        boost::asio::steady_timer timer;
        std::optional<std::vector<uint8_t>> response{};
    };

    std::shared_ptr<Message> transmit(struct mctp* mctp, mctp_eid_t destEid,
                                      std::vector<uint8_t>&& payload,
                                      std::vector<uint8_t>&& privateData,
                                      boost::asio::io_context& ioc);

    bool receive(struct mctp* mctp, mctp_eid_t srcEid, uint8_t msgTag,
                 std::vector<uint8_t>&& response, boost::asio::io_context& ioc);

    void dispose(mctp_eid_t destEid, const std::shared_ptr<Message>& message);

  private:
    struct Tags
    {
        std::optional<uint8_t> next() const;
        void emplace(uint8_t flag);
        void erase(uint8_t flag);

        uint8_t bits{0xff};
    };

    struct Endpoint
    {
        Tags availableTags;
        std::map<uint8_t, std::shared_ptr<Message>> transmittedMessages{};
        std::map<size_t, std::shared_ptr<Message>> queuedMessages{};

        size_t msgCounter{0u};
        void transmitQueuedMessages(struct mctp* mctp, mctp_eid_t destEid);
    };

    std::map<mctp_eid_t, Endpoint> endpoints{};
};
} // namespace mctpd