#ifndef RSOPPRF_TEST_H_
#define RSOPPRF_TEST_H_

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "cryptoTools/Common/TestCollection.h"
#include "psi/okvs/defines.h"
#include "psi/okvs/paxos.h"

// #include "volePSI/Defines.h"
// #include "volePSI/config.h"

// #ifdef VOLE_PSI_ENABLE_OPPRF

namespace primihub::crypto {

void RsOpprf_eval_blk_test();
void RsOpprf_eval_blk_mtx_test();

void RsOpprf_eval_u8_test();
void RsOpprf_eval_u8_mtx_test();
}  // namespace primihub::crypto
// #endif
#endif