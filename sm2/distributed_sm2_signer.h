#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <iostream>

#include "distributed_sm2_pubkey.h"

#ifndef DISTRIBUTEDSM2SIGNATURE_H
#define DISTRIBUTEDSM2SIGNATURE_H

namespace primihub::crypto {
class DistributedSM2Signature {
 public:
  friend class DistributedSM2Verification;

  DistributedSM2Pubkeygen& m_party;
  EC_KEY* ec_key_;
  const BIGNUM* order_;
  const EC_GROUP* group_;
  const EC_POINT* generator_;
  EC_POINT* PublicKey_;
  std::string& ID_;
  std::string Z_A_;
  BIGNUM* r_;
  BIGNUM* S_;

  DistributedSM2Signature(DistributedSM2Pubkeygen& party);

  int cal_Q1(const std::string& msg);

  std::string generate_za(void);

  std::string unicoder(std::string msg) {
    size_t len = msg.length() / 2;

    char* charArray = new char[len + 1];
    charArray[len] = '\0';

    for (size_t i = 0; i < len; ++i) {
      std::string byteString = msg.substr(i * 2, 2);
      char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
      charArray[i] = byte;
    }

    std::string unicode_str(charArray);

    delete[] charArray;
    return unicode_str;
  }

  std::string generate_hash(const std::string& za);
  std::string generate_hash(const unsigned char* za, uint16_t message_len);

  int export_e_Q1(std::string& dest_str);

  int import_e_Q1(const std::string& msg);

  int cal_S2(void);

  int export_r_S2_S3(std::string& dest_str);

  int import_r_S2_S3(const std::string& dest_str);

  int get_signature_result(std::string& r, std::string& s);

  ~DistributedSM2Signature();

 private:
  BIGNUM* k1_;
  BIGNUM* e_;
  EC_POINT* Q1_;

  BIGNUM* D_;
  BIGNUM* k2_;
  BIGNUM* k3_;
  BIGNUM* S2_;
  BIGNUM* S3_;
};
}  // namespace primihub::crypto
#endif