#include "HEVEC/HEval.hpp"

#include <cstring>
#include <immintrin.h>
#include <map>

#include "hexl/eltwise/eltwise-add-mod.hpp"
#include "hexl/eltwise/eltwise-fma-mod.hpp"
#include "hexl/eltwise/eltwise-mult-mod.hpp"
#include "hexl/eltwise/eltwise-sub-mod.hpp"
#include "hexl/ntt/ntt.hpp"
#include "hexl/number-theory/number-theory.hpp"
#include "omp.h"

#include "HEVEC/MLWESwitchingKey.hpp"
#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/Exception.hpp"
#include "HEVEC/Polynomial.hpp"
#include "HEVEC/SwitchingKey.hpp"

namespace HEVEC {

HEval::HEval(u64 logRank) : logRank_(logRank), rank_(1ULL << logRank) {
  omp_set_max_active_levels(1);
  omp_set_num_threads(N_THREAD);

  ntts_[rank_ + MOD_Q] = intel::hexl::NTT(rank_, MOD_Q);
  ntts_[rank_ + MOD_P] = intel::hexl::NTT(rank_, MOD_P);
  ntts_[DEGREE + MOD_Q] = intel::hexl::NTT(DEGREE, MOD_Q);
  ntts_[DEGREE + MOD_P] = intel::hexl::NTT(DEGREE, MOD_P);

  inv_[rank_] = std::vector<u64>(2 * rank_);
  for (u64 i = 0; i < 2 * rank_; ++i)
    inv_[rank_][i] = intel::hexl::PowMod(i, rank_ - 1, 2 * rank_);
  inv_[DEGREE] = std::vector<u64>(2 * DEGREE);
  for (u64 i = 0; i < 2 * DEGREE; ++i)
    inv_[DEGREE][i] = intel::hexl::PowMod(i, DEGREE - 1, 2 * DEGREE);

  for (u64 log = 0; log <= LOG_DEGREE; ++log) {
    const u64 mod = 1ULL << log;
    bitRev_[mod] = std::vector<u64>(mod);
    for (u64 i = 1; i < mod; ++i)
      bitRev_[mod][i] = intel::hexl::ReverseBits(i, log);
  }

  barr_[MOD_Q] = Q_BARR;
  barr_[MOD_P] = P_BARR;
};

u64 HEval::getInv(u64 op, u64 mod) { return inv_[mod][op]; }

u64 HEval::getBitRev(u64 op, u64 mod) { return bitRev_[mod][op]; }

void HEval::add(Polynomial &res, const Polynomial &op1, const Polynomial &op2) {
  if (op1.getIsNTT() != op2.getIsNTT())
    throw InvalidNTTStateException();
  if (res.getMod() != op1.getMod() || op1.getMod() != op2.getMod())
    throw InvalidModulusException();

  intel::hexl::EltwiseAddMod(res.getData(), op1.getData(), op2.getData(),
                             op1.getDegree(), op1.getMod());
  res.setIsNTT(op1.getIsNTT());
}

void HEval::sub(Polynomial &res, const Polynomial &op1, const Polynomial &op2) {
  if (op1.getIsNTT() != op2.getIsNTT())
    throw InvalidNTTStateException();
  if (res.getMod() != op1.getMod() || op1.getMod() != op2.getMod())
    throw InvalidModulusException();

  intel::hexl::EltwiseSubMod(res.getData(), op1.getData(), op2.getData(),
                             op1.getDegree(), op1.getMod());

  res.setIsNTT(op1.getIsNTT());
}

void HEval::mult(Polynomial &res, const Polynomial &op1,
                 const Polynomial &op2) {
  if (!op1.getIsNTT() || !op2.getIsNTT())
    throw InvalidNTTStateException();
  if (res.getMod() != op1.getMod() || op1.getMod() != op2.getMod())
    throw InvalidModulusException();

  intel::hexl::EltwiseMultMod(res.getData(), op1.getData(), op2.getData(),
                              op1.getDegree(), op1.getMod(), 1);
  res.setIsNTT(true);
}

void HEval::mult(Polynomial &res, const Polynomial &op1, u64 op2) {
  intel::hexl::EltwiseFMAMod(res.getData(), op1.getData(), op2, nullptr,
                             op1.getDegree(), op1.getMod(), 1);
  res.setIsNTT(op1.getIsNTT());
}

void HEval::mad(Polynomial &res, const Polynomial &op1, u64 op2,
                const Polynomial &op3) {
  if (op1.getIsNTT() != op3.getIsNTT())
    throw InvalidNTTStateException();
  intel::hexl::EltwiseFMAMod(res.getData(), op1.getData(), op2, op3.getData(),
                             op1.getDegree(), op1.getMod(), 1);
  res.setIsNTT(op1.getIsNTT());
}

void HEval::shift(Polynomial &res, const Polynomial &op, u64 exponent,
                  u64 rank) {
  if (op.getIsNTT())
    throw InvalidNTTStateException();
  if (op.getData() == res.getData())
    throw SameDataReferenceException();

  const u64 stack = op.getDegree() / rank;

#pragma omp parallel for
  for (u64 i = 0; i < rank; ++i) {
    u64 idx = (exponent + i) & (2 * rank - 1);
    if (idx < rank)
      for (u64 j = 0; j < stack; ++j)
        res[idx * stack + j] = op[i * stack + j];
    else
      for (u64 j = 0; j < stack; ++j)
        res[(idx - rank) * stack + j] =
            op[i * stack + j] ? (op.getMod() - op[i * stack + j]) : 0;
  }
  res.setIsNTT(false);
}

void HEval::aut(Polynomial &res, const Polynomial &op, u64 exponent, u64 rank) {
  if (op.getIsNTT())
    throw InvalidNTTStateException();
  if (op.getData() == res.getData())
    throw SameDataReferenceException();

  const u64 stack = op.getDegree() / rank;

  for (u64 i = 0; i < rank; ++i) {
    u64 idx = (i * exponent) & (2 * rank - 1);
    bool sign = true;
    if (idx >= rank) {
      idx -= rank;
      sign = false;
    }
    for (u64 j = 0; j < stack; ++j) {
      if (sign)
        res[idx * stack + j] = op[i * stack + j];
      else
        res[idx * stack + j] =
            op[i * stack + j] ? (op.getMod() - op[i * stack + j]) : 0;
    }
  }
  res.setIsNTT(false);
}

void HEval::normMod(Polynomial &res, const Polynomial &op) {

  const u64 halfMod = op.getMod() >> 1;
  const bool isSmallPrime = halfMod <= res.getMod();
  const u64 diff =
      res.getMod() -
      (isSmallPrime ? op.getMod()
                    : intel::hexl::BarrettReduce64(op.getMod(), res.getMod(),
                                                   barr_[res.getMod()]));

#pragma omp parallel for
  for (u64 i = 0; i < op.getDegree(); ++i) {
    u64 temp = op[i];
    if (temp > halfMod)
      temp += diff;
    if (!isSmallPrime)
      temp =
          intel::hexl::BarrettReduce64(temp, res.getMod(), barr_[res.getMod()]);
    res[i] = temp;
  }
  res.setIsNTT(false);
}

void HEval::extract(Polynomial &res, const Polynomial &op) {
  if (op.getIsNTT())
    throw InvalidNTTStateException();
  const u64 stack = op.getDegree() / res.getDegree();

#pragma omp parallel for
  for (u64 i = 0; i < res.getDegree(); ++i)
    res[i] = op[(i + 1) * stack - 1];
  res.setIsNTT(false);
}

void HEval::ntt(Polynomial &res, const Polynomial &op, u64 inputModFactor,
                u64 outputModFactor) {
  if (op.getIsNTT())
    throw InvalidNTTStateException();
  if (res.getMod() != op.getMod())
    throw InvalidModulusException();

  res.setIsNTT(true);
  ntts_[op.getDegree() + op.getMod()].ComputeForward(
      res.getData(), op.getData(), inputModFactor, outputModFactor);
}

void HEval::intt(Polynomial &res, const Polynomial &op, u64 inputModFactor,
                 u64 outputModFactor) {
  if (!op.getIsNTT())
    throw InvalidNTTStateException();
  if (res.getMod() != op.getMod())
    throw InvalidModulusException();

  res.setIsNTT(false);
  ntts_[op.getDegree() + op.getMod()].ComputeInverse(
      res.getData(), op.getData(), inputModFactor, outputModFactor);
}

void HEval::add(MLWECiphertext &res, const MLWECiphertext &op1,
                const MLWECiphertext &op2) {
#pragma omp parallel for
  for (u64 i = 0; i < op1.getStack() + 1; ++i) {
    if (i < op1.getStack())
      add(res.getA(i), op1.getA(i), op2.getA(i));
    else
      add(res.getB(), op1.getB(), op2.getB());
  }
}

void HEval::sub(MLWECiphertext &res, const MLWECiphertext &op1,
                const MLWECiphertext &op2) {
#pragma omp parallel for
  for (u64 i = 0; i < op1.getStack() + 1; ++i) {
    if (i < op1.getStack())
      sub(res.getA(i), op1.getA(i), op2.getA(i));
    else
      sub(res.getB(), op1.getB(), op2.getB());
  }
}

void HEval::mult(MLWECiphertext &res, const MLWECiphertext &op1, u64 op2) {
#pragma omp parallel for
  for (u64 i = 0; i < op1.getStack() + 1; ++i) {
    if (i < op1.getStack())
      mult(res.getA(i), op1.getA(i), op2);
    else
      mult(res.getB(), op1.getB(), op2);
  }
}

void HEval::shift(MLWECiphertext &res, const MLWECiphertext &op, u64 exponent) {
#pragma omp parallel for
  for (u64 i = 0; i < op.getStack() + 1; ++i) {
    if (i < op.getStack())
      shift(res.getA(i), op.getA(i), exponent, op.getRank());
    else
      shift(res.getB(), op.getB(), exponent, op.getRank());
  }
}

void HEval::aut(MLWECiphertext &res, const MLWECiphertext &op, u64 exponent) {
#pragma omp parallel for
  for (u64 i = 0; i < op.getStack() + 1; ++i) {
    if (i < op.getStack())
      aut(res.getA(i), op.getA(i), exponent, op.getRank());
    else
      aut(res.getB(), op.getB(), exponent, op.getRank());
  }
}

void HEval::aut(Ciphertext &res, const MLWECiphertext &op,
                const std::vector<MLWESwitchingKey> &autedModPackKeys,
                u64 exponent) {
  Polynomial temp(op.getRank(), MOD_Q), tempModQ(op.getRank(), MOD_Q),
      tempModP(op.getRank(), MOD_P);
  MLWESwitchingKey multed(op.getRank());

  const u64 stack = op.getDegree() / op.getRank();

  res.setIsNTT(false);

#pragma omp parallel for
  for (u64 j = 0; j < op.getRank(); ++j) {
    u64 idx = (j * exponent) & (2 * op.getRank() - 1);
    if (idx < op.getRank())
      res.getB()[idx * stack] = op.getB()[j];
    else
      res.getB()[idx * stack - op.getDegree()] = MOD_Q - op.getB()[j];
  }
  { // i = 0
    aut(temp, op.getA(0), exponent, op.getRank());
    normMod(tempModP, temp);

    ntt(temp, temp);
    ntt(tempModP, tempModP);

#pragma omp parallel for
    for (u64 j = 0; j < stack; ++j) {
      mult(multed.getPolyAModQ(j), temp, autedModPackKeys[0].getPolyAModQ(j));
      mult(multed.getPolyBModQ(j), temp, autedModPackKeys[0].getPolyBModQ(j));
      mult(multed.getPolyAModP(j), tempModP,
           autedModPackKeys[0].getPolyAModP(j));
      mult(multed.getPolyBModP(j), tempModP,
           autedModPackKeys[0].getPolyBModP(j));
    }
  }
  for (u64 i = 1; i < stack; ++i) {
    aut(temp, op.getA(i), exponent, op.getRank());
    normMod(tempModP, temp);

    ntt(temp, temp);
    ntt(tempModP, tempModP);

#pragma omp parallel for
    for (u64 j = 0; j < stack; ++j) {
      Polynomial tempQ(op.getRank(), MOD_Q), tempP(op.getRank(), MOD_P);
      mult(tempQ, temp, autedModPackKeys[i].getPolyAModQ(j));
      add(multed.getPolyAModQ(j), multed.getPolyAModQ(j), tempQ);
      mult(tempQ, temp, autedModPackKeys[i].getPolyBModQ(j));
      add(multed.getPolyBModQ(j), multed.getPolyBModQ(j), tempQ);
      mult(tempP, tempModP, autedModPackKeys[i].getPolyAModP(j));
      add(multed.getPolyAModP(j), multed.getPolyAModP(j), tempP);
      mult(tempP, tempModP, autedModPackKeys[i].getPolyBModP(j));
      add(multed.getPolyBModP(j), multed.getPolyBModP(j), tempP);
    }
  }

#pragma omp parallel for
  for (u64 i = 0; i < stack; ++i) {
    Polynomial tempQ(op.getRank(), MOD_Q);
    intt(multed.getPolyAModP(i), multed.getPolyAModP(i));
    normMod(tempQ, multed.getPolyAModP(i));
    intt(multed.getPolyAModQ(i), multed.getPolyAModQ(i));
    sub(multed.getPolyAModQ(i), multed.getPolyAModQ(i), tempQ);
    mult(multed.getPolyAModQ(i), multed.getPolyAModQ(i), INVERSE_P_MOD_Q);

    intt(multed.getPolyBModP(i), multed.getPolyBModP(i));
    normMod(tempQ, multed.getPolyBModP(i));
    intt(multed.getPolyBModQ(i), multed.getPolyBModQ(i));
    sub(multed.getPolyBModQ(i), multed.getPolyBModQ(i), tempQ);
    mult(multed.getPolyBModQ(i), multed.getPolyBModQ(i), INVERSE_P_MOD_Q);
  }
#pragma omp parallel for
  for (u64 i = 0; i < multed.getRank(); ++i) {
    for (u64 j = 0; j < multed.getStack(); ++j) {
      res.getA()[i * stack + j] = multed.getPolyAModQ(j)[i];
      res.getB()[i * stack + j] += multed.getPolyBModQ(j)[i];
    }
  }

  ntt(res.getA(), res.getA());
  ntt(res.getB(), res.getB());
}

void HEval::add(Ciphertext &res, const Ciphertext &op1, const Ciphertext &op2) {
  if (op1.getIsNTT() != op2.getIsNTT())
    throw InvalidNTTStateException();
  if (op1.getIsExtended() != op2.getIsExtended())
    throw InvalidExtendedStateException();
  add(res.getA(), op1.getA(), op2.getA());
  add(res.getB(), op1.getB(), op2.getB());
  if (op1.getIsExtended())
    add(res.getC(), op1.getC(), op2.getC());
  res.setIsNTT(op1.getIsNTT());
}

void HEval::sub(Ciphertext &res, const Ciphertext &op1, const Ciphertext &op2) {
  if (op1.getIsNTT() != op2.getIsNTT())
    throw InvalidNTTStateException();
  if (op1.getIsExtended() != op2.getIsExtended())
    throw InvalidExtendedStateException();
  sub(res.getA(), op1.getA(), op2.getA());
  sub(res.getB(), op1.getB(), op2.getB());
  if (op1.getIsExtended())
    sub(res.getC(), op1.getC(), op2.getC());
  res.setIsNTT(op1.getIsNTT());
}

void HEval::mult(Ciphertext &res, const Ciphertext &op1,
                 const Ciphertext &op2) {
  if (!op1.getIsNTT() || !op2.getIsNTT())
    throw InvalidNTTStateException();
  if (!res.getIsExtended())
    throw InvalidExtendedStateException();
  mult(res.getA(), op1.getA(), op2.getA());
  mult(res.getC(), op1.getB(), op2.getB());

  Polynomial temp(op1.getA().getDegree(), MOD_Q);
  mult(temp, op1.getA(), op2.getB());
  mult(res.getB(), op1.getB(), op2.getA());
  add(res.getB(), temp, res.getB());
}

void HEval::mult(Ciphertext &res, const Ciphertext &op1,
                 const Polynomial &op2) {
  mult(res.getA(), op1.getA(), op2);
  mult(res.getB(), op1.getB(), op2);
}

void HEval::mult(Ciphertext &res, const Ciphertext &op1, u64 op2) {
  mult(res.getA(), op1.getA(), op2);
  mult(res.getB(), op1.getB(), op2);
  if (res.getIsExtended())
    mult(res.getC(), op1.getC(), op2);
}

void HEval::shift(Ciphertext &res, const Ciphertext &op, u64 exponent) {
  shift(res.getA(), op.getA(), exponent, op.getDegree());
  shift(res.getB(), op.getB(), exponent, op.getDegree());
}

void HEval::aut(Ciphertext &res, const Ciphertext &op,
                const SwitchingKey &autKey, u64 exponent) {
  aut(res.getA(), op.getA(), exponent, op.getDegree());
  aut(res.getB(), op.getB(), exponent, op.getDegree());
  keySwitch(res, res, autKey);
}

void HEval::relin(Ciphertext &res, const Ciphertext &op,
                  const SwitchingKey &relinKey) {
  if (!op.getIsExtended())
    throw InvalidExtendedStateException();
  keySwitch(res, op, relinKey);
}

void HEval::modPack(Ciphertext &res, const std::vector<MLWECiphertext> &op,
                    const std::vector<SwitchingKey> &modPackKeys) {
  const u64 stack = res.getDegree() / getRank();

  res.setIsNTT(false);

#pragma omp parallel for
  for (u64 i = 0; i < getRank(); ++i) {
    for (u64 j = 0; j < stack; ++j)
      res.getB()[i * stack + j] = op[j].getB()[i];
  }
  Polynomial tempQ(DEGREE, MOD_Q), tempP(DEGREE, MOD_P),
      tempModQ(DEGREE, MOD_Q), tempModP(DEGREE, MOD_P),
      polyAModQ(DEGREE, MOD_Q), polyAModP(DEGREE, MOD_P),
      polyBModQ(DEGREE, MOD_Q), polyBModP(DEGREE, MOD_P);
  polyAModQ.setIsNTT(true);
  polyAModP.setIsNTT(true);
  polyBModQ.setIsNTT(true);
  polyBModP.setIsNTT(true);
  for (u64 i = 0; i < stack; ++i) {
#pragma omp parallel for
    for (u64 j = 0; j < getRank(); ++j) {
      for (u64 k = 0; k < stack; ++k)
        tempModQ[j * stack + k] = op[k].getA(i)[j];
    }
    tempModQ.setIsNTT(false);
    normMod(tempModP, tempModQ);

    ntt(tempModQ, tempModQ);
    ntt(tempModP, tempModP);

    mult(tempQ, tempModQ, modPackKeys[i].getPolyAModQ());
    add(polyAModQ, polyAModQ, tempQ);
    mult(tempQ, tempModQ, modPackKeys[i].getPolyBModQ());
    add(polyBModQ, polyBModQ, tempQ);

    mult(tempP, tempModP, modPackKeys[i].getPolyAModP());
    add(polyAModP, polyAModP, tempP);
    mult(tempP, tempModP, modPackKeys[i].getPolyBModP());
    add(polyBModP, polyBModP, tempP);
  }
  intt(polyAModP, polyAModP);
  normMod(tempModQ, polyAModP);

  ntt(tempModQ, tempModQ);
  sub(polyAModQ, polyAModQ, tempModQ);

  mult(res.getA(), polyAModQ, INVERSE_P_MOD_Q);
  intt(polyBModP, polyBModP);
  normMod(tempModQ, polyBModP);

  ntt(tempModQ, tempModQ);
  sub(tempModQ, polyBModQ, tempModQ);
  ntt(res.getB(), res.getB());
  mad(res.getB(), tempModQ, INVERSE_P_MOD_Q, res.getB());
}

void HEval::modPack(Polynomial &res, const std::vector<Polynomial> &op) {
  const u64 stack = res.getDegree() / getRank();

  res.setIsNTT(false);

#pragma omp parallel for
  for (u64 i = 0; i < getRank(); ++i) {
    for (u64 j = 0; j < stack; ++j)
      res[i * stack + j] = op[j][i];
  }
  ntt(res, res);
}

void HEval::ntt(Ciphertext &res, const Ciphertext &op, u64 inputModFactor,
                u64 outputModFactor) {
  if (op.getIsNTT())
    throw InvalidNTTStateException();
  ntt(res.getA(), op.getA(), inputModFactor, outputModFactor);
  ntt(res.getB(), op.getB(), inputModFactor, outputModFactor);
}

void HEval::intt(Ciphertext &res, const Ciphertext &op, u64 inputModFactor,
                 u64 outputModFactor) {
  if (!op.getIsNTT())
    throw InvalidNTTStateException();
  intt(res.getA(), op.getA(), inputModFactor, outputModFactor);
  intt(res.getB(), op.getB(), inputModFactor, outputModFactor);
}

void HEval::multithreadMultSum(Ciphertext &res,
                               const std::vector<Ciphertext> &op1,
                               const std::vector<Ciphertext> &op2) {
  if (!op1[0].getIsNTT() || !op2[0].getIsNTT())
    throw InvalidNTTStateException();
  constexpr u64 DEGREE_PER_THREAD = DEGREE / N_THREAD;

  const u64 gap = op1.size() / op2.size();

  Polynomial temp(op1[0].getDegree(), MOD_Q);
#pragma omp parallel for
  for (u64 i = 0; i < N_THREAD; ++i) {
    for (u64 j = 0; j < op2.size(); ++j) {
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[j * gap].getA().getData() + DEGREE_PER_THREAD * i,
          op2[j].getA().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getA().getData() + DEGREE_PER_THREAD * i,
                                 res.getA().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[j * gap].getA().getData() + DEGREE_PER_THREAD * i,
          op2[j].getB().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getB().getData() + DEGREE_PER_THREAD * i,
                                 res.getB().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[j * gap].getB().getData() + DEGREE_PER_THREAD * i,
          op2[j].getA().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getB().getData() + DEGREE_PER_THREAD * i,
                                 res.getB().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[j * gap].getB().getData() + DEGREE_PER_THREAD * i,
          op2[j].getB().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getC().getData() + DEGREE_PER_THREAD * i,
                                 res.getC().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
    }
  }
  res.setIsNTT(true);
}

void HEval::multithreadMultSum(Ciphertext &res,
                               const std::vector<Ciphertext> &op1,
                               const std::vector<Polynomial> &op2) {
  if (!op1[0].getIsNTT() || !op2[0].getIsNTT())
    throw InvalidNTTStateException();
  constexpr u64 DEGREE_PER_THREAD = DEGREE / N_THREAD;
  const u64 gap = op1.size() / op2.size();

  Polynomial temp(op1[0].getDegree(), MOD_Q);
#pragma omp parallel for
  for (u64 i = 0; i < N_THREAD; ++i) {
    for (u64 j = 0; j < op2.size(); ++j) {
      intel::hexl::EltwiseMultMod(temp.getData() + DEGREE_PER_THREAD * i,
                                  op1[j * gap].getA().getData() +
                                      DEGREE_PER_THREAD * i,
                                  op2[j].getData() + DEGREE_PER_THREAD * i,
                                  DEGREE_PER_THREAD, MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getA().getData() + DEGREE_PER_THREAD * i,
                                 res.getA().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(temp.getData() + DEGREE_PER_THREAD * i,
                                  op1[j * gap].getB().getData() +
                                      DEGREE_PER_THREAD * i,
                                  op2[j].getData() + DEGREE_PER_THREAD * i,
                                  DEGREE_PER_THREAD, MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getB().getData() + DEGREE_PER_THREAD * i,
                                 res.getB().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
    }
  }
  res.setIsNTT(true);
}

void HEval::bitRevedMultithreadMultSum(Ciphertext &res,
                                       const std::vector<Ciphertext> &op1,
                                       const std::vector<Ciphertext> &op2) {
  if (!op1[0].getIsNTT() || !op2[0].getIsNTT())
    throw InvalidNTTStateException();
  constexpr u64 DEGREE_PER_THREAD = DEGREE / N_THREAD;

  Polynomial temp(op1[0].getA().getDegree(), MOD_Q);
#pragma omp parallel for
  for (u64 i = 0; i < N_THREAD; ++i) {
    for (u64 j = 0; j < rank_; ++j) {
      const u64 bitRev = getBitRev(j, rank_);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[bitRev].getA().getData() + DEGREE_PER_THREAD * i,
          op2[j].getA().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getA().getData() + DEGREE_PER_THREAD * i,
                                 res.getA().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[bitRev].getA().getData() + DEGREE_PER_THREAD * i,
          op2[j].getB().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getB().getData() + DEGREE_PER_THREAD * i,
                                 res.getB().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[bitRev].getB().getData() + DEGREE_PER_THREAD * i,
          op2[j].getA().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getB().getData() + DEGREE_PER_THREAD * i,
                                 res.getB().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
      intel::hexl::EltwiseMultMod(
          temp.getData() + DEGREE_PER_THREAD * i,
          op1[bitRev].getB().getData() + DEGREE_PER_THREAD * i,
          op2[j].getB().getData() + DEGREE_PER_THREAD * i, DEGREE_PER_THREAD,
          MOD_Q, 1);
      intel::hexl::EltwiseAddMod(res.getC().getData() + DEGREE_PER_THREAD * i,
                                 res.getC().getData() + DEGREE_PER_THREAD * i,
                                 temp.getData() + DEGREE_PER_THREAD * i,
                                 DEGREE_PER_THREAD, MOD_Q);
    }
  }
  res.setIsNTT(true);
}

u64 HEval::getRank() const { return rank_; }

void HEval::keySwitch(Ciphertext &res, const Ciphertext &op,
                      const SwitchingKey &swtKey) {
  Polynomial tempModQ(op.getDegree(), MOD_Q), tempModP(op.getDegree(), MOD_P),
      polyAModQ(op.getDegree(), MOD_Q), polyAModP(op.getDegree(), MOD_P),
      polyBModQ(op.getDegree(), MOD_Q), polyBModP(op.getDegree(), MOD_P);
  if (op.getIsNTT()) {
    intt(tempModQ, op.getA());
    normMod(tempModP, tempModQ);
    mult(polyAModQ, op.getA(), swtKey.getPolyAModQ());
    mult(polyBModQ, op.getA(), swtKey.getPolyBModQ());
  } else {
    ntt(tempModQ, op.getA());
    normMod(tempModP, op.getA());
    mult(polyAModQ, tempModQ, swtKey.getPolyAModQ());
    mult(polyBModQ, tempModQ, swtKey.getPolyBModQ());
  }
  ntt(tempModP, tempModP);
  mult(polyAModP, tempModP, swtKey.getPolyAModP());
  mult(polyBModP, tempModP, swtKey.getPolyBModP());
  intt(polyAModP, polyAModP);
  normMod(tempModQ, polyAModP);
  ntt(tempModQ, tempModQ);
  sub(res.getA(), polyAModQ, tempModQ);
  if (op.getIsExtended())
    mad(res.getA(), res.getA(), INVERSE_P_MOD_Q, op.getB());
  else {
    mult(res.getA(), res.getA(), INVERSE_P_MOD_Q);
  }
  intt(polyBModP, polyBModP);
  normMod(tempModQ, polyBModP);
  if (op.getIsNTT())
    ntt(tempModQ, tempModQ);
  else {
    ntt(tempModQ, tempModQ);
    ntt(res.getB(), op.getB());
  }
  sub(tempModQ, polyBModQ, tempModQ);
  if (op.getIsExtended())
    mad(res.getB(), tempModQ, INVERSE_P_MOD_Q, op.getC());
  else {
    ntt(res.getB(), op.getB());
    mad(res.getB(), tempModQ, INVERSE_P_MOD_Q, res.getB());
  }
}

} // namespace HEVEC