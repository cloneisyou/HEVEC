#pragma once

#include <cmath>
#include <openssl/rand.h>

#include "Polynomial.hpp"
#include "Type.hpp"

namespace HEVEC {

class Random {
public:
  static u8 getRandomU8();
  static u32 getRandomU32();
  static u64 getRandomU64();
  static void getRandomSeed(u8 *seed);

  static void sampleUniform(Polynomial &res);
  static void sampleUniformWithSeed(Polynomial &res, const u8 *seed);
  static void sampleDiscreteGaussian(Polynomial &res);
  static void sampleDiscreteGaussian(Polynomial &res_q, Polynomial &res_p);
};

} // namespace HEVEC