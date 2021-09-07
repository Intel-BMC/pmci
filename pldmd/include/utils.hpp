/**
 * Copyright © 2021 Intel Corporation
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

#pragma once

#include <sstream>
#include <vector>

namespace utils
{

/** @brief Helper to print vector
 *
 * Helper to print an array of bytes(eg: Request,Response) with log level DEBUG
 *
 * @param msg[in] - Message to print along the vector
 * @param vec[in] - Vector of bytes to print
 *
 */
void printVect(const std::string& msg, const std::vector<uint8_t>& vec);

/** @brief Helper to convert a number to uint32
 *
 * Helper to convert a number to uint32 type
 * This particular override is used in arm32 architectures.
 *
 * @param num[in] - Number to convert to uint32
 * @return - Result of the conversion to uint32
 *
 */
inline uint32_t to_uint32(uint32_t num)
{
    return num;
}

/** @brief Helper to convert a number to uint32
 *
 * Helper to convert a number to uint32 type
 * This particular override is used in x86_64 architecture.
 *
 * @param num[in] - Number to convert to uint32
 * @return - Result of the conversion to uint32
 *
 */
inline uint32_t to_uint32(uint64_t num)
{
    return static_cast<uint32_t>(num);
}

} // namespace utils
