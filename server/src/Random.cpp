#include "HEVEC/Random.hpp"

#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <stdexcept>

#include "hexl/eltwise/eltwise-reduce-mod.hpp"
#include "hexl/hexl.hpp"

#include "HEVEC/Const.hpp"
#include "HEVEC/Exception.hpp"
#include "HEVEC/Polynomial.hpp"

namespace HEVEC {
u8 Random::getRandomU8() {
  u8 rnd;
  if (RAND_bytes(&rnd, sizeof(rnd)) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return rnd;
}
u32 Random::getRandomU32() {
  u32 rnd;
  if (RAND_bytes(reinterpret_cast<u8 *>(&rnd), sizeof(rnd)) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return rnd;
}

u64 Random::getRandomU64() {
  u64 rnd;
  if (RAND_bytes(reinterpret_cast<u8 *>(&rnd), sizeof(rnd)) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return rnd;
}

void Random::getRandomSeed(u8 *seed) {
  if (RAND_bytes(seed, SEED_SIZE) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
}

void Random::sampleUniform(Polynomial &res) {
  RAND_bytes(reinterpret_cast<u8 *>(res.getData()),
             sizeof(u64) * res.getDegree());
  intel::hexl::EltwiseReduceMod(res.getData(), res.getData(), res.getDegree(),
                                res.getMod(), res.getMod(), 1);
}

void Random::sampleUniformWithSeed(Polynomial &res, const u8 *seed) {
  EVP_RAND *rand = EVP_RAND_fetch(nullptr, "CTR-DRBG", nullptr);
  EVP_RAND_CTX *rctx = EVP_RAND_CTX_new(rand, nullptr);

  EVP_RAND_instantiate(rctx, 256, 0, seed, SEED_SIZE, nullptr);

  EVP_RAND_generate(rctx, reinterpret_cast<u8 *>(res.getData()),
                    sizeof(u64) * res.getDegree(), 256, 0, nullptr, 0);

  EVP_RAND_CTX_free(rctx);
  EVP_RAND_free(rand);
  intel::hexl::EltwiseReduceMod(res.getData(), res.getData(), res.getDegree(),
                                res.getMod(), res.getMod(), 1);
}

void Random::sampleDiscreteGaussian(Polynomial &res) {
  constexpr double TWO_TO_32 = static_cast<double>(1ULL << 32);

  std::vector<u32> rand(res.getDegree());

  RAND_bytes(reinterpret_cast<u8 *>(rand.data()),
             sizeof(u32) * res.getDegree());

  for (u64 i = 0; i < res.getDegree() / 2; ++i) {
    // Box-Muller transform
    double rnd1 = static_cast<double>(rand[2 * i]) / TWO_TO_32;
    double rnd2 = static_cast<double>(rand[2 * i + 1]) / TWO_TO_32;
    double theta = rnd1 * M_PI * 2;
    double radius = sqrt(-2.0 * log(rnd2)) * GAUSSIAN_ERROR_STDEV;
    i64 val1 = std::lround(radius * cos(theta));
    i64 val2 = std::lround(radius * sin(theta));
    res[i * 2] = (val1 < 0) ? res.getMod() + val1 : val1;
    res[i * 2 + 1] = (val2 < 0) ? res.getMod() + val2 : val2;
  }
}

void Random::sampleDiscreteGaussian(Polynomial &res_q, Polynomial &res_p) {
  constexpr double TWO_TO_32 = static_cast<double>(1ULL << 32);

  std::vector<u32> rand(res_q.getDegree());

  RAND_bytes(reinterpret_cast<u8 *>(rand.data()),
             sizeof(u32) * res_q.getDegree());

  for (u64 i = 0; i < res_q.getDegree() / 2; ++i) {
    // Box-Muller transform
    double rnd1 = static_cast<double>(rand[2 * i]) / TWO_TO_32;
    double rnd2 = static_cast<double>(rand[2 * i + 1]) / TWO_TO_32;
    double theta = rnd1 * M_PI * 2;
    double radius = sqrt(-2.0 * log(rnd2)) * GAUSSIAN_ERROR_STDEV;
    i64 val1 = std::lround(radius * cos(theta));
    i64 val2 = std::lround(radius * sin(theta));
    res_q[i * 2] = (val1 < 0) ? res_q.getMod() + val1 : val1;
    res_p[i * 2] = (val1 < 0) ? res_p.getMod() + val1 : val1;
    res_q[i * 2 + 1] = (val2 < 0) ? res_q.getMod() + val2 : val2;
    res_p[i * 2 + 1] = (val2 < 0) ? res_p.getMod() + val2 : val2;
  }
}

} // namespace HEVEC