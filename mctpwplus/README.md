# MCTP Wrapper C++ Library

MCTP wrapper library is introduced to make the life of developers easy.
People who write applications that uses MCTP layer for communication will
have to discover and talk to mctp endpoints. Each endpoint will be 
identified by an integer identifier called endpoint id or EID.
These applications can be PLDM daemon or NVMe MI daemon etc.
In some environments mctp stack may be implemented as
a service which exposes its APIs over DBus. On some machines it may be
implemented directly in kernel. Each application developer can seperate MCTP
communication to another layer to accomodate this changes. But a library
makes things much easier.

For example the APIs provided by this library allow user to
* Discover EIDs
* Send request and receive response
* Listen for EIDs added and removed dynamically

So the implementation is not a concern to the developer. Developer can focus
on the application logic and implement it.

## Building
This library uses CMake as build system. The build is tested only on Ubuntu
 18.04.

Create a build subdirectory and execute the cmake command.
```
cmake -DYOCTO_DEPENDENCIES=OFF -DBUILD_EXAMPLES=ON ../
```
This will fetch and build prequisites if needed including boost sdbusplus
 etc. Then make the library using
```
make
```
The output is libcmtpwplus.so which can be linked against applications that
wish to use MCTP for communication.

## Example
The main class provided by mctpwplus is MCTPWrapper. The object of this
class can be used for all MCTP communication purposes. MCTPWrapper class
takes one MCTPConfiguration object in constructor. The configuration object
specifies what is the message type and which binding type to use.
 ```cpp
    boost::asio::io_context io;
    MCTPConfiguration config(mctpw::MessageType::pldm,
                             mctpw::BindingType::mctpOverSmBus);
    MCTPWrapper mctpWrapper(io, config, nullptr, nullptr);
 ```
Then the mctpWrapper object can be used to discover and talk to EIDs.
```cpp
// To detect available endpoints
mctpWrapper.detectMctpEndpoints(yield);
// ep will have all available EIDs in the system
auto& ep = mctpWrapper.getEndpointMap();

// Send request to EID and receive response
std::vector<uint8_t> request2 = {1, 143, 0, 3, 0, 0, 0, 0, 1, 0};
auto rcvStatus = mctpWrapper.sendReceiveYield(
    yield, eid, request2, std::chrono::milliseconds(100));
```
There are more examples available in examples directory which deal with more
specific functions.

## Public APIs

### MCTPConfiguration

MCTPConfiguration objects can define parameters like MCTP message type and
binding type. MCTPWrapper constructor expects an MCTPConfiguration object. So
configuration object must be created before creating wrapper object.
 ```cpp
    MCTPConfiguration config(mctpw::MessageType::pldm,
                             mctpw::BindingType::mctpOverSmBus);
 ```
Using the above config object to create wrapper will.
* Filter MCTP services with binding type SMBus
* Inside those services only EIDs which supports message type PLDM will be added
to endpoint list.

There is also option to use VendorId filtering if binding type is PCIe.

### Constructor
MCTPWrapper class defines 2 types of constructors. One variant takes boost
io_context and other one takes shared_ptr to boost asio connection. Internally
MCTPWrapper needs a sdbusplus connection object to work. If io_context is
passed then a new connection object will be created. Or an existing connection
object can be shared also.<br>
Example 1.
```cpp
    boost::asio::io_context io;
    MCTPConfiguration config(mctpw::MessageType::pldm,
                             mctpw::BindingType::mctpOverSmBus);
    MCTPWrapper mctpWrapper(io, config, nullptr, nullptr);
 ```
Example 2.
```cpp
    boost::asio::io_context io;
    auto connection = std::make_shared<sdbusplus::asio::connection>(io);
    MCTPConfiguration config(mctpw::MessageType::pldm,
                             mctpw::BindingType::mctpOverSmBus);
    MCTPWrapper mctpWrapper(connection, config, nullptr, nullptr);
 ```
Then the mctpWrapper object can be used to discover and talk to EIDs.

### DetectMctpEndpoints
It also has two variants. Async and yield based.
```cpp
void detectMctpEndpointsAsync(StatusCallback&& callback);
boost::system::error_code
        detectMctpEndpoints(boost::asio::yield_context yield);
```
This API must be called before accessing any send receive functions. This API
will scan the system for available MCTP services. Detect end points inside
them. Filter them based on given message type. And populate endpoint list.
MCTPWrapper will know how to send payload to an EID only after this API is
called.
```cpp
boost::asio::spawn(
[&mctpWrapper](boost::asio::yield_context yield) {
    auto ec = mctpWrapper.detectMctpEndpoints(yield);
    auto epMap = mctpWrapper.getEndpointMap();
    for (const auto& [eid, serviceName] : epMap)
    {
        std::cout << "Eid " << static_cast<int>(eid) << " on "
                << serviceName.second << '\n';
    }
});
```
```cpp
auto registerCB = [](boost::system::error_code ec,
                                        void* ctx) {
    if (ec)
    {
        std::cout << "Error: " << ec << std::endl;
        return;
    }
    if (ctx)
    {
        auto wrapper = reinterpret_cast<MCTPWrapper*>(ctx);
        auto epMap = wrapper->getEndpointMap();
        for (const auto& [eid, serviceName] : epMap)
        {
            std::cout << "Eid " << static_cast<int>(eid) << " on "
                    << serviceName.second << '\n';
        }
    }
};
mctpWrapper.detectMctpEndpointsAsync(registerCB);
```
### SendReceive API
```cpp
void sendReceiveAsync(ReceiveCallback receiveCb, eid_t dstEId,
                          const ByteArray& request,
                          std::chrono::milliseconds timeout);
std::pair<boost::system::error_code, ByteArray>
        sendReceiveYield(boost::asio::yield_context yield, eid_t dstEId,
                         const ByteArray& request,
                         std::chrono::milliseconds timeout);
```
SendReceive APIs can be used after detectMctpEndpoints is called. It also has yield and async variant.<br>
Async Example
```cpp
auto recvCB = [](boost::system::error_code err,
                     const std::vector<uint8_t>& response) {
    if (err)
    {
        // Error
    }
    else
    {
        // Valid response
    }
};
std::vector<uint8_t> request = {1, 143, 0, 3, 0, 0, 0, 0, 1, 0};
mctpWrapper.sendReceiveAsync(recvCB, eid, request,
                                     std::chrono::milliseconds(100));
```
Yield Example
```cpp
std::vector<uint8_t> request2 = {1, 143, 0, 3, 0, 0, 0, 0, 1, 0};
auto rcvStatus = mctpWrapper.sendReceiveYield(
    yield, eid, request2, std::chrono::milliseconds(100));
if (rcvStatus.first)
{
    std::cout << "Yield Error " << rcvStatus.first.message();
}
else
{
    // Valid response
}
```