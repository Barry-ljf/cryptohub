#ifndef RSOPRF_TEST_H_
#define RSOPRF_TEST_H_

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "cryptoTools/Common/CLP.h"

namespace primihub::crypto {

void RsOprf_eval_test();
void RsOprf_mal_test();
void RsOprf_reduced_test();
}  // namespace primihub::crypto
#endif