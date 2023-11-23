#include "distributed_sm2_signer.h"

#include <glog/logging.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "proto/distributed_signature.pb.h"

using DistributedSignature::SM2_e_Q1_msg;
using DistributedSignature::SM2_r_s2_s3_msg;

namespace primihub::crypto {
DistributedSM2Signature::DistributedSM2Signature(DistributedSM2Pubkeygen &party)
    : m_party(party), ID_(party.m_ID) {
  ec_key_ = EC_KEY_new_by_curve_name(NID_sm2);
  group_ = EC_KEY_get0_group(ec_key_);
  order_ = EC_GROUP_get0_order(group_);
  generator_ = EC_GROUP_get0_generator(group_);
  this->D_ = BN_new();
  this->D_ = party.D_;
  this->PublicKey_ = EC_POINT_new(group_);
  this->PublicKey_ = party.PublicKey_;
}

std::string DistributedSM2Signature::generate_za(void) {
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *xG = BN_new();
  BIGNUM *yG = BN_new();
  BIGNUM *xA = BN_new();
  BIGNUM *yA = BN_new();

  // const EC_GROUP *group = EC_KEY_get0_group(ec_key_);
  BIGNUM *p = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  EC_GROUP_get_curve(group_, p, a, b, ctx);

  // Use the values of p, a, and b
  EC_POINT_get_affine_coordinates_GFp(group_, generator_, xG, yG, nullptr);
  EC_POINT_get_affine_coordinates_GFp(group_, m_party.PublicKey_, xA, yA,
                                      nullptr);

  unsigned char a_str[BN_num_bytes(a)];
  unsigned char b_str[BN_num_bytes(b)];
  unsigned char xG_str[BN_num_bytes(xG)];
  unsigned char yG_str[BN_num_bytes(yG)];
  unsigned char xA_str[BN_num_bytes(xA)];
  unsigned char yA_str[BN_num_bytes(yA)];

  // char *a_str_1 = BN_bn2hex(a);
  // char *b_str_1 = BN_bn2hex(b);
  // char *xG_str = BN_bn2hex(xG);
  // char *yG_str = BN_bn2hex(yG);
  // char *xA_str = BN_bn2hex(xA);
  // char *yA_str = BN_bn2hex(yA);

  BN_bn2bin(a, a_str);
  BN_bn2bin(b, b_str);
  BN_bn2bin(xG, xG_str);
  BN_bn2bin(yG, yG_str);
  BN_bn2bin(xA, xA_str);
  BN_bn2bin(yA, yA_str);

  // LOG(INFO) << "a_str_1: " << a_str_1;
  // LOG(INFO) << "b_str_1: " << b_str_1;
  // LOG(INFO) << "a: " << a_str;
  // LOG(INFO) << "b: " << b_str;
  // LOG(INFO) << "xG: " << xG_str;
  // LOG(INFO) << "yG: " << yG_str;
  // LOG(INFO) << "xA: " << xA_str;
  // LOG(INFO) << "yA: " << yA_str;

  int total_length = 2 + strlen(ID_.c_str()) + sizeof(a_str) + sizeof(b_str) +
                     sizeof(xG_str) + sizeof(yG_str) + sizeof(xA_str) +
                     sizeof(yA_str);

  uint32_t entlenA = ID_.length() * 8;

  LOG(INFO) << "entlenA: " << entlenA;
  LOG(INFO) << "ID_: " << ID_;

  unsigned char byte0 = static_cast<unsigned char>((entlenA >> 8) & 0xFF);
  unsigned char byte1 = static_cast<unsigned char>(entlenA & 0xFF);
  unsigned char ZA_temp[total_length];
  ZA_temp[0] = byte0;
  ZA_temp[1] = byte1;

  // debug
  //  ZA_temp[0] = '\x00';
  //  ZA_temp[1] = '\x80';
  ////unsigned char array do not need this.
  // if (byte0 == '\0') {
  //   ZA_temp[0] = '\x00';
  //   LOG(INFO) << "byte0 is equal to '\\0' ";
  // }

  unsigned char ID_C[ID_.length()];
  for (size_t i = 0; i < ID_.length(); i++) {
    ID_C[i] = static_cast<unsigned char>(ID_[i]);
  }

  // LOG(INFO) << "byte0: " << byte0;
  // LOG(INFO) << "byte1: " << byte1;

  memcpy(ZA_temp + 2, ID_C, ID_.length());
  memcpy(ZA_temp + sizeof(ID_C) + 2, (a_str), sizeof(a_str));
  memcpy(ZA_temp + sizeof(ID_C) + 2 + sizeof(a_str), (b_str), sizeof(b_str));
  memcpy(ZA_temp + sizeof(ID_C) + 2 + sizeof(a_str) + sizeof(b_str), (xG_str),
         sizeof(xG_str));
  memcpy(ZA_temp + sizeof(ID_C) + 2 + sizeof(a_str) + sizeof(b_str) +
             sizeof(xG_str),
         (yG_str), sizeof(yG_str));
  memcpy(ZA_temp + sizeof(ID_C) + 2 + sizeof(a_str) + sizeof(b_str) +
             sizeof(xG_str) + sizeof(yG_str),
         (xA_str), sizeof(xA_str));
  memcpy(ZA_temp + sizeof(ID_C) + 2 + sizeof(a_str) + sizeof(b_str) +
             sizeof(xG_str) + sizeof(yG_str) + sizeof(xA_str),
         (yA_str), sizeof(yA_str));

  BN_clear_free(p);
  BN_clear_free(a);
  BN_clear_free(b);
  BN_clear_free(xG);
  BN_clear_free(yG);
  BN_clear_free(xA);
  BN_clear_free(yA);
  BN_CTX_free(ctx);

  LOG(INFO) << "ZA_temp: " << ZA_temp;
  LOG(INFO) << "ZA_temp length: " << sizeof(ZA_temp);

  // do not use this to free unsigned char array
  // OPENSSL_free(a_str);
  // OPENSSL_free(b_str);
  // OPENSSL_free(xG_str);
  // OPENSSL_free(yG_str);
  // OPENSSL_free(xA_str);
  // OPENSSL_free(yA_str);

  std::string HASH_Z_A_ = generate_hash(ZA_temp, sizeof(ZA_temp));
  LOG(INFO) << "HASH_Z_A_temp: " << HASH_Z_A_;
  // LOG(INFO)<< "\nZA_temp LENGTH"<< sizeof(ZA_temp);
  //  std::string result_str(reinterpret_cast<char *>(ZA_temp));
  Z_A_ = HASH_Z_A_;
  return HASH_Z_A_;
}

std::string DistributedSM2Signature::generate_hash(const std::string &za_m) {
  // turn ZA(za) into byte array
  // const unsigned char *user_identifier_bytes =
  //     reinterpret_cast<const unsigned char *>(za_m.c_str());

  OpenSSL_add_all_digests();
  const EVP_MD *md = EVP_sm3();

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_MD_CTX_init(mdctx);

  EVP_DigestInit_ex(mdctx, md, nullptr);
  EVP_DigestUpdate(mdctx, za_m.c_str(), za_m.length());

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_length;
  // use to hash byte array
  EVP_DigestFinal_ex(mdctx, hash, &hash_length);

  // // turn byte array into string.
  // unsigned char hash_value[hash_length];

  std::stringstream digest_str;
  digest_str << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < hash_length; ++i) {
    digest_str << std::setw(2) << static_cast<unsigned int>(hash[i]);
  }
  // std::string digest_str;
  // for (unsigned int i = 0; i < hash_length; i++) {
  //   char hex_byte[3];
  //   snprintf(hex_byte, sizeof(hex_byte), "%02x", hash_value[i]);
  //   digest_str += hex_byte;
  // }
  EVP_MD_CTX_free(mdctx);
  return digest_str.str();
}

std::string DistributedSM2Signature::generate_hash(const unsigned char *za_m,
                                                   uint16_t message_len) {
  // turn ZA(za) into byte array
  // const unsigned char *user_identifier_bytes =
  //     reinterpret_cast<const unsigned char *>(za_m.c_str());

  OpenSSL_add_all_digests();
  const EVP_MD *md = EVP_sm3();

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_MD_CTX_init(mdctx);

  EVP_DigestInit_ex(mdctx, md, nullptr);
  EVP_DigestUpdate(mdctx, za_m, message_len);

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_length;
  // use to hash byte array
  EVP_DigestFinal_ex(mdctx, hash, &hash_length);

  // // turn byte array into string.
  // unsigned char hash_value[hash_length];

  std::stringstream digest_str;
  digest_str << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < hash_length; ++i) {
    digest_str << std::setw(2) << static_cast<unsigned int>(hash[i]);
  }
  // std::string digest_str;
  // for (unsigned int i = 0; i < hash_length; i++) {
  //   char hex_byte[3];
  //   snprintf(hex_byte, sizeof(hex_byte), "%02x", hash_value[i]);
  //   digest_str += hex_byte;
  // }
  EVP_MD_CTX_free(mdctx);
  return digest_str.str();
}

int DistributedSM2Signature::cal_Q1(const std::string &msg) {
  // concat string (Za || M)
  Z_A_ = generate_za();

  // debug
  //  std::string m_Z_M =
  //      "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F36D657373"
  //      "61676520646967657374";
  //  LOG(INFO) << "Z_A_:" << Z_A_;
  //  LOG(INFO) << "m_Z_M:" << m_Z_M;

  std::stringstream msg_temp;

  for (char ch : msg) {
    msg_temp << std::hex
             << static_cast<unsigned int>(static_cast<unsigned char>(ch));
  }

  std::string m_Z_M_1 = Z_A_ + msg_temp.str();
  LOG(INFO) << "m_Z_M_1:" << m_Z_M_1;
  std::string unicoder_m_Z_M = unicoder(m_Z_M_1);
  std::string e_str = generate_hash(unicoder_m_Z_M);

  LOG(INFO) << "HASH(M-):" << e_str;
  e_ = BN_new();
  BN_hex2bn(&e_, e_str.c_str());
  // debug
  char *e_str_1;
  e_str_1 = BN_bn2hex(e_);
  LOG(INFO) << "initial e_str value: " << e_str_1;
  OPENSSL_free(e_str_1);

  k1_ = BN_new();
  // set k1 for debug
  BN_hex2bn(&k1_, "1");
  // BN_rand_range(k1_, order_);

  // calculate Q1 = k1 * G
  Q1_ = EC_POINT_new(group_);
  EC_POINT_mul(group_, Q1_, nullptr, generator_, k1_, nullptr);
  // if(!EC_POINT_mul(group_, Q1, nullptr, generator_, scalar, nullptr)){
  // }
  // delete[] charArray;
  // auto part_1 = std::make_pair(e, Q1);
  return 0;
}

int DistributedSM2Signature::export_e_Q1(std::string &dest_str) {
  auto e_size = BN_num_bytes(e_);
  // std::vector<unsigned char> e_vec(e_size);
  std::string str_e;
  str_e.resize(e_size);
  BN_bn2bin(e_, reinterpret_cast<unsigned char *>(str_e.data()));
  // debug
  char *e_str;
  e_str = BN_bn2hex(e_);
  LOG(INFO) << "export e_str value: " << e_str;
  OPENSSL_free(e_str);
  char *q1_str =
      EC_POINT_point2hex(group_, Q1_, POINT_CONVERSION_COMPRESSED, nullptr);

  SM2_e_Q1_msg msg;
  msg.set_str_e(std::move(str_e));
  msg.set_str_q1(std::string(q1_str));

  free(q1_str);
  q1_str = nullptr;

  if (!msg.SerializeToString(&dest_str)) {
    LOG(ERROR) << "Serialize proto msg that contain e and Q1 failed.";
    return -1;
  }

  return 0;
}

int DistributedSM2Signature::import_e_Q1(const std::string &dest_str) {
  SM2_e_Q1_msg msg;
  if (!msg.ParseFromString(dest_str)) {
    LOG(ERROR) << "Parse from string that contain e and Q1 failed.";
    return -1;
  }

  const std::string &str_e = msg.str_e();
  const unsigned char *e_ptr =
      reinterpret_cast<const unsigned char *>(str_e.data());
  e_ = BN_bin2bn(e_ptr, str_e.size(), nullptr);
  // debug
  char *e_str;
  e_str = BN_bn2hex(e_);
  LOG(INFO) << "import e_str value: " << e_str;
  OPENSSL_free(e_str);

  const std::string &str_q1 = msg.str_q1();
  EC_POINT *q1 = EC_POINT_new(group_);
  if (!EC_POINT_hex2point(group_, reinterpret_cast<const char *>(str_q1.data()),
                          q1, nullptr)) {
    LOG(ERROR) << "Convert hex string to ec_point failed.";
    return -1;
  }

  return 0;
}

int DistributedSM2Signature::cal_S2(void) {
  k2_ = BN_new();
  k3_ = BN_new();
  S2_ = BN_new();
  S3_ = BN_new();
  r_ = BN_new();
  // D2_ = BN_new();
  // BN_rand_range(D2_, order_); // private key

  // Q2=k2*G
  EC_POINT *Q2;
  EC_POINT *temp, *temp1;
  Q2 = EC_POINT_new(group_);
  temp = EC_POINT_new(group_);
  temp1 = EC_POINT_new(group_);

  BIGNUM *x1 = BN_new();
  BIGNUM *y1 = BN_new();
  BIGNUM *x2 = BN_new();
  BIGNUM *y2 = BN_new();
  BIGNUM *temp2 = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  do {
    // determine do..while with ki.
    // BN_rand_range(k2_, order_);
    // BN_rand_range(k3_, order_);

    // debug set k2,k3 for debug: k = k1 *k3 + k2
    BN_hex2bn(
        &k2_,
        "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC20");
    BN_hex2bn(&k3_, "1");
    EC_POINT_mul(group_, Q2, k2_, nullptr, nullptr, ctx);

    //(x1,y1) = k3 * Q1 + Q2
    EC_POINT_mul(group_, temp, nullptr, generator_, k3_, nullptr);
    EC_POINT_add(group_, temp1, temp, Q2, nullptr);

    //(x1,y1) r=x1+e modn
    EC_POINT_get_affine_coordinates_GFp(group_, temp1, x1, y1, nullptr);
    EC_POINT_get_affine_coordinates_GFp(group_, Q2, x2, y2, nullptr);
    BN_mod_add(r_, e_, x1, order_, ctx);

  } while (BN_is_zero(r_));

  // debug:
  char *bignum_str;
  char *bignum_str_1;
  char *k2_str;
  char *k3_str;
  char *r_str;
  char *e_str;

  bignum_str = BN_bn2hex(x1);
  bignum_str_1 = BN_bn2hex(y1);
  k2_str = BN_bn2hex(k2_);
  k3_str = BN_bn2hex(k3_);
  r_str = BN_bn2hex(r_);
  e_str = BN_bn2hex(e_);

  LOG(INFO) << "P0 x1 key value: " << bignum_str;
  LOG(INFO) << "P1 y1 key value: " << bignum_str_1;
  LOG(INFO) << "k2_str value: " << k2_str;
  LOG(INFO) << "k3_str value: " << k3_str;
  LOG(INFO) << "r_str value: " << r_str;
  LOG(INFO) << "e_str value: " << e_str;

  OPENSSL_free(bignum_str);
  OPENSSL_free(bignum_str_1);
  OPENSSL_free(k2_str);
  OPENSSL_free(k3_str);
  OPENSSL_free(r_str);
  OPENSSL_free(e_str);

  // S2 = D2 * K3
  BN_mod_mul(S2_, D_, k3_, order_, ctx);

  // calculate s3
  BN_mod_add(temp2, k2_, r_, order_, ctx);
  BN_mod_mul(S3_, temp2, D_, order_, ctx);

  // debug
  char *D_str;
  D_str = BN_bn2hex(D_);
  LOG(INFO) << "import D_str value: " << D_str;
  OPENSSL_free(D_str);

  BN_free(x1);
  BN_free(y1);
  BN_free(temp2);
  BN_free(k2_);
  BN_free(k3_);
  EC_POINT_free(temp);
  EC_POINT_free(temp1);
  BN_CTX_free(ctx);

  return 0;
}

int DistributedSM2Signature::get_signature_result(std::string &res_r,
                                                  std::string &res_s) {
  BIGNUM *D1_k1 = BN_new();
  BIGNUM *D1_k1_S2 = BN_new();
  BIGNUM *D1_S3 = BN_new();
  BIGNUM *sum_temp = BN_new();

  S_ = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  // D1_ = BN_new();
  // BN_rand_range(D1_, order_); // private key

  // determine D1
  BN_mod_mul(D1_k1, k1_, D_, order_, ctx);
  BN_mod_mul(D1_k1_S2, D1_k1, S2_, order_, ctx);
  BN_mod_mul(D1_S3, S3_, D_, order_, ctx);
  BN_mod_add(sum_temp, D1_k1_S2, D1_S3, order_, ctx);

  // calculate s
  BN_mod_sub(S_, sum_temp, r_, order_, ctx);
  if (S_ == 0) {
    LOG(ERROR) << "The signature result is zero, please retry the signature "
                  "process.";
    return -1;
  }

  // debug
  char *S2_str;
  char *S3_str;
  char *D_str;

  S2_str = BN_bn2hex(S2_);
  S3_str = BN_bn2hex(S3_);
  D_str = BN_bn2hex(D_);

  LOG(INFO) << "initial S2_str value: " << S2_str;
  LOG(INFO) << "initial S3_str value: " << S3_str;
  LOG(INFO) << "initial D_str value: " << D_str;

  OPENSSL_free(S2_str);
  OPENSSL_free(D_str);
  OPENSSL_free(S3_str);

  char *str = BN_bn2hex(r_);
  char *str1 = BN_bn2hex(S_);

  res_r = std::string(str);
  res_s = std::string(str1);

  free(str);
  free(str1);
  BN_free(D1_k1);
  BN_free(D1_k1_S2);
  BN_free(D1_S3);
  BN_free(r_);
  BN_free(S2_);
  BN_free(S3_);
  BN_free(k1_);
  BN_free(e_);
  EC_POINT_free(Q1_);
  BN_free(S_);
  BN_free(sum_temp);
  BN_CTX_free(ctx);

  return 0;
}

int DistributedSM2Signature::export_r_S2_S3(std::string &dest_str) {
  // Convert r,S2,S3 to string.
  auto r_size = BN_num_bytes(r_);
  // std::vector<unsigned char> r_vec(r_size);
  std::string r_str;
  r_str.resize(r_size);
  BN_bn2bin(r_, reinterpret_cast<unsigned char *>(r_str.data()));

  auto S2_size = BN_num_bytes(S2_);
  // std::vector<unsigned char> S2_vec(S2_size);
  std::string r_s2;
  r_s2.resize(S2_size);
  BN_bn2bin(S2_, reinterpret_cast<unsigned char *>(r_s2.data()));

  auto S3_size = BN_num_bytes(S3_);
  // std::vector<unsigned char> S3_vec(S3_size);
  std::string r_s3;
  r_s3.resize(S3_size);
  BN_bn2bin(S3_, reinterpret_cast<unsigned char *>(r_s3.data()));

  SM2_r_s2_s3_msg msg;
  msg.set_str_r(std::move(r_str));
  msg.set_str_s2(std::move(r_s2));
  msg.set_str_s3(std::move(r_s3));

  if (!msg.SerializeToString(&dest_str)) {
    LOG(ERROR) << "Serialize proto msg that contain r, s2, s3 failed.";
    return -1;
  }

  BN_free(r_);
  BN_free(S2_);
  BN_free(S3_);

  return 0;
}

int DistributedSM2Signature::import_r_S2_S3(const std::string &dest_str) {
  SM2_r_s2_s3_msg msg;
  if (!msg.ParseFromString(dest_str)) {
    LOG(ERROR) << "Parse from string that contain r, s2, s3 failed.";
    return -1;
  }

  const std::string &str_r = msg.str_r();
  const unsigned char *ptr_r =
      reinterpret_cast<const unsigned char *>(str_r.data());
  r_ = BN_bin2bn(ptr_r, str_r.size(), nullptr);

  const std::string &str_s2 = msg.str_s2();
  const unsigned char *ptr_s2 =
      reinterpret_cast<const unsigned char *>(str_s2.data());
  S2_ = BN_bin2bn(ptr_s2, str_s2.size(), nullptr);

  const std::string &str_s3 = msg.str_s3();
  const unsigned char *ptr_s3 =
      reinterpret_cast<const unsigned char *>(str_s3.data());
  S3_ = BN_bin2bn(ptr_s3, str_s3.size(), nullptr);

  return 0;
}

DistributedSM2Signature::~DistributedSM2Signature() { EC_KEY_free(ec_key_); }
}  // namespace primihub::crypto