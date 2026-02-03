#pragma once

#include "Type.hpp"

namespace HEVEC {

constexpr int N_THREAD = 64;

constexpr u64 LOG_DEGREE = 12;
constexpr u64 HAMMING_WEIGHT = 2730;
constexpr double GAUSSIAN_ERROR_STDEV = 3.2;

constexpr u64 MOD_Q = 18014398491918337;  // 54 bit
constexpr u64 MOD_P = 36028797005856769; // 55 bit
constexpr u64 INVERSE_P_MOD_Q = 995681451208133;

constexpr double LOG_SCALE = 26.25;

// constexpr u64 MOD_Q = 9007199252119553;  // 53 bit
// constexpr u64 MOD_P = 72057594036879361; // 56 bit
// constexpr u64 INVERSE_P_MOD_Q = 8096969226141425;

// constexpr double LOG_SCALE = 25.75;

constexpr u64 DEGREE = 1ULL << LOG_DEGREE;
constexpr u64 P_MOD_Q = MOD_P % MOD_Q;
constexpr u64 Q_BARR = (static_cast<u128>(1) << 64) / MOD_Q;
constexpr u64 P_BARR = (static_cast<u128>(1) << 64) / MOD_P;

constexpr u64 PIR_PER_COEFF_BITS = 2;
constexpr u64 PIR_PAYLOAD_SIZE = DEGREE >> PIR_PER_COEFF_BITS;

constexpr u64 AES_KEY_SIZE = 32;
constexpr u64 SEED_SIZE = 128;
} // namespace HEVEC