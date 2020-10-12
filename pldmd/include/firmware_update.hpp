/**
 * Copyright © 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sdbusplus/asio/object_server.hpp>
#include <vector>

namespace pldm
{
namespace fwu
{
using FWUVariantType = std::variant<uint16_t, uint32_t, std::string>;

enum class DescriptorIdentifierType : uint16_t
{
    pciVendorID = 0,
    ianaEnterpriseID = 1,
    uuid = 2,
    pnpVendorID = 3,
    acpiVendorID = 4,
    pciDeviceID = 0x0100,
    pciSubsystemVendorID = 0x0101,
    pciSubsystemID = 0x0102,
    pciRevisionID = 0x0103,
    pnpProductIdentifier = 0x0104,
    acpiProductIdentifier = 0x0105
};

struct DescriptorHeader
{
    DescriptorIdentifierType type;
    uint16_t size;
};

class PLDMFWUpdate
{
  public:
    PLDMFWUpdate() = delete;
    PLDMFWUpdate(boost::asio::yield_context _yield, const pldm_tid_t _tid);
    ~PLDMFWUpdate();

    /** @brief runs inventory commands
     */
    std::optional<std::map<std::string, FWUVariantType>> runInventoryCommands();

  private:
    /** @brief run query device identifiers command
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int runQueryDeviceIdentifiers();
    /** @brief This API is used for processing descriptor data of standard sizes
     */
    template <typename T>
    void processDescriptor(const DescriptorHeader& header, const T& data);

    /** @brief This API is used for processing descriptor data of non-standard
     * sizes and bigger sizes.
     */
    void processDescriptor(const DescriptorHeader& header,
                           const std::vector<uint8_t>& data);

    /** @brief This API is used for unpacking descriptor data based on the
     * descriptor type.
     */
    void unpackDescriptors(const uint8_t count,
                           const std::vector<uint8_t>& data);

    boost::asio::yield_context yield;
    pldm_tid_t tid;
    std::map<std::string, FWUVariantType> fwuProperties;
    const uint16_t timeout = 100;
    const size_t retryCount = 3;
};
} // namespace fwu
} // namespace pldm