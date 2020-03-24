#include "MCTPBinding.hpp"

#include <systemd/sd-bus.h>

#include "gtest/gtest.h"

class MctpdBaseTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

TEST_F(MctpdBaseTest, MctpdEmptyTest)
{
    GTEST_SKIP();
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
