#include "MCTPBinding.hpp"

#include "libmctp.h"

MctpBinding::MctpBinding()
{
    eid = 0;
    mctp_init();
    // TODO:Add MCTP Binding interfaces here
}
