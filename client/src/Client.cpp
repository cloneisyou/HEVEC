#include "HEVEC/Client.hpp"

#include <cstring>
#include <immintrin.h>
#include <queue>
#include <utility>

#include "hexl/number-theory/number-theory.hpp"

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/Message.hpp"
#include "HEVEC/Polynomial.hpp"
#include "HEVEC/Random.hpp"
#include "HEVEC/SecretKey.hpp"
#include "HEVEC/SwitchingKey.hpp"

namespace HEVEC {

Client::Client(u64 log_rank)
    : eval_(log_rank),
      invRank_(intel::hexl::PowMod(1ULL << log_rank, MOD_Q - 2, MOD_Q)) {}

void Client::genSecKey(SecretKey &res) {
  std::vector<u64> indices(DEGREE);

  for (u64 i = 0; i < DEGREE; ++i) {
    indices[i] = i;
  }
  // Fisher-Yates Shuffle
  for (size_t i = DEGREE - 1; i > 0; --i) {
    size_t j = Random::getRandomU32() % (i + 1);
    std::swap(indices[i], indices[j]);
  }
  for (size_t i = 0; i < HAMMING_WEIGHT; i++) {
    bool sign = Random::getRandomU8() & 1;
    res.getPolyQ()[indices[i]] = sign ? 1 : (MOD_Q - 1);
    res.getPolyP()[indices[i]] = sign ? 1 : (MOD_P - 1);
  }
  eval_.ntt(res.getPolyQ(), res.getPolyQ());
  eval_.ntt(res.getPolyP(), res.getPolyP());
}

void Client::genRelinKey(SwitchingKey &res, const SecretKey &secKey) {
  Polynomial modifiedKey(DEGREE, MOD_Q);

  eval_.mult(modifiedKey, secKey.getPolyQ(), secKey.getPolyQ());
  genSwtKey(res, secKey, modifiedKey);
}

void Client::genInvAutKeys(std::vector<SwitchingKey> &res,
                           const SecretKey &secKey, u64 rank) {
  const u64 stack = DEGREE / rank;
  const u64 step = 2 * DEGREE / rank;

  res.clear();
  res.resize(rank);

  Polynomial tempQ(DEGREE, MOD_Q), tempP(DEGREE, MOD_P);

  SecretKey invAut;
  eval_.intt(tempQ, secKey.getPolyQ());
  eval_.intt(tempP, secKey.getPolyP());

  for (u64 i = 0; i < rank; ++i) {
    eval_.aut(invAut.getPolyQ(), tempQ, eval_.getInv(step * i + 1, DEGREE),
              DEGREE);
    eval_.ntt(invAut.getPolyQ(), invAut.getPolyQ());
    eval_.aut(invAut.getPolyP(), tempP, eval_.getInv(step * i + 1, DEGREE),
              DEGREE);
    eval_.ntt(invAut.getPolyP(), invAut.getPolyP());
    genSwtKey(res[i], invAut, secKey.getPolyQ());
  }
}

void Client::genModPackKeys(std::vector<SwitchingKey> &res,
                            const SecretKey &secKey) {
  const u64 stack = DEGREE / getRank();

  res.clear();
  res.resize(stack);

  Polynomial temp(DEGREE, MOD_Q), modifiedKey(DEGREE, MOD_Q);

  res.clear();
  res.resize(stack);

  eval_.intt(temp, secKey.getPolyQ());

  for (u64 i = 0; i < stack; ++i) {
    memset(modifiedKey.getData(), 0, DEGREE * sizeof(u64));
    modifiedKey.setIsNTT(false);
    for (u64 j = 0; j < getRank(); ++j)
      modifiedKey[stack * j] = temp[(j + 1) * stack - 1 - i];
    eval_.ntt(modifiedKey, modifiedKey);
    genSwtKey(res[i], secKey, modifiedKey);
  }
}

void Client::genAutedModPackKeys(AutedModPackKeys &res,
                                 const SecretKey &secKey) {
  const u64 stack = DEGREE / getRank();

  for (u64 i = 0; i < getRank(); ++i) {
    Polynomial temp(DEGREE, MOD_Q), autedKey(DEGREE, MOD_Q),
        modifiedKey(DEGREE, MOD_Q);

    eval_.intt(temp, secKey.getPolyQ());
    eval_.aut(autedKey, temp, 2 * i + 1, getRank());
    for (u64 j = 0; j < stack; ++j) {
      for (u64 k = 0; k < getRank(); ++k)
        modifiedKey[stack * k] = autedKey[(k + 1) * stack - 1 - j];
      eval_.ntt(temp, modifiedKey);
      genSwtKey(res.getKeys()[i][j], secKey, temp);
    }
  }
}

void Client::genInvAutedModPackKeys(AutedModPackMLWEKeys &res,
                                    const SecretKey &secKey) {
  const u64 stack = DEGREE / getRank();

  for (u64 i = 0; i < getRank(); ++i) {
    Polynomial inttedSecKey(DEGREE, MOD_Q), temp(DEGREE, MOD_Q),
        tempQ(DEGREE, MOD_Q), tempP(DEGREE, MOD_P), modifiedKey(DEGREE, MOD_Q);

    SecretKey autedKey;

    const u64 exponent = 2 * i + 1;

    eval_.intt(inttedSecKey, secKey.getPolyQ());
    eval_.aut(autedKey.getPolyQ(), inttedSecKey, eval_.getInv(exponent, DEGREE),
              DEGREE);
    eval_.ntt(autedKey.getPolyQ(), autedKey.getPolyQ());
    eval_.intt(tempP, secKey.getPolyP());
    eval_.aut(autedKey.getPolyP(), tempP, eval_.getInv(exponent, DEGREE),
              DEGREE);
    eval_.ntt(autedKey.getPolyP(), autedKey.getPolyP());
    for (u64 j = 0; j < stack; ++j) {
      SwitchingKey swtKey;
      modifiedKey.setIsNTT(false);
      for (u64 k = 0; k < getRank(); ++k)
        modifiedKey[stack * k] = inttedSecKey[(k + 1) * stack - 1 - j];
      eval_.ntt(temp, modifiedKey);
      genSwtKey(swtKey, autedKey, temp);
      eval_.intt(tempQ, swtKey.getPolyAModQ());
      for (u64 k = 0; k < stack; ++k) {
        for (u64 l = 0; l < getRank(); ++l)
          res.getKeys()[i][j].getPolyAModQ(k)[l] = tempQ[l * stack + k];
        eval_.ntt(res.getKeys()[i][j].getPolyAModQ(k),
                  res.getKeys()[i][j].getPolyAModQ(k));
      }
      eval_.intt(tempP, swtKey.getPolyAModP());
      for (u64 k = 0; k < stack; ++k) {
        for (u64 l = 0; l < getRank(); ++l)
          res.getKeys()[i][j].getPolyAModP(k)[l] = tempP[l * stack + k];
        eval_.ntt(res.getKeys()[i][j].getPolyAModP(k),
                  res.getKeys()[i][j].getPolyAModP(k));
      }
      eval_.intt(tempQ, swtKey.getPolyBModQ());
      for (u64 k = 0; k < stack; ++k) {
        for (u64 l = 0; l < getRank(); ++l)
          res.getKeys()[i][j].getPolyBModQ(k)[l] = tempQ[l * stack + k];
        eval_.ntt(res.getKeys()[i][j].getPolyBModQ(k),
                  res.getKeys()[i][j].getPolyBModQ(k));
      }
      eval_.intt(tempP, swtKey.getPolyBModP());
      for (u64 k = 0; k < stack; ++k) {
        for (u64 l = 0; l < getRank(); ++l)
          res.getKeys()[i][j].getPolyBModP(k)[l] = tempP[l * stack + k];
        eval_.ntt(res.getKeys()[i][j].getPolyBModP(k),
                  res.getKeys()[i][j].getPolyBModP(k));
      }
    }
  }
}

void Client::encode(Polynomial &res, const Message &msg, double scale) {
  const u64 stack = res.getDegree() / msg.getDegree();

  for (u64 i = 0; i < msg.getDegree(); ++i) {
    bool sign = msg[i] > 0;
    u64 value = std::abs(msg[i]) * scale;
    res[(i + 1) * stack - 1] = sign ? value : (MOD_Q - value);
  }
}

void Client::decode(Message &res, const Polynomial &ptxt, double scale) {
  for (u64 i = 0; i < ptxt.getDegree(); ++i) {
    res[i] =
        ptxt[i] < (MOD_Q / 2) ? ptxt[i] : -static_cast<double>(MOD_Q - ptxt[i]);
    res[i] /= scale;
  }
}

void Client::encrypt(Ciphertext &res, const Polynomial &ptxt,
                     const SecretKey &secKey) {
  Polynomial as(DEGREE, MOD_Q), e(DEGREE, MOD_Q);

  Random::sampleUniform(res.getA());
  res.getA().setIsNTT(true);
  eval_.mult(as, res.getA(), secKey.getPolyQ());
  eval_.intt(res.getA(), res.getA());
  eval_.intt(as, as);
  eval_.sub(res.getB(), ptxt, as);
  Random::sampleDiscreteGaussian(e);
  eval_.add(res.getB(), res.getB(), e);
}

void Client::encrypt(Ciphertext &res, const Message &msg,
                     const SecretKey &secKey, double scale) {
  Polynomial ptxt(DEGREE, MOD_Q);

  encode(ptxt, msg, scale);
  encrypt(res, ptxt, secKey);
}

void Client::encrypt(MLWECiphertext &res, const Polynomial &ptxt,
                     const SecretKey &secKey) {
  Ciphertext temp;

  encrypt(temp, ptxt, secKey);
  res.getB().setIsNTT(false);
  eval_.extract(res.getB(), temp.getB());
  for (u64 i = 0; i < res.getStack(); ++i) {
    res.getA(i).setIsNTT(false);
    for (u64 j = 0; j < res.getRank(); ++j)
      res.getA(i)[j] = temp.getA()[j * res.getStack() + i];
  }
}

void Client::encrypt(MLWECiphertext &res, const Message &msg,
                     const SecretKey &secKey, double scale) {
  Polynomial ptxt(DEGREE, MOD_Q);

  encode(ptxt, msg, scale);
  encrypt(res, ptxt, secKey);
}

void Client::decrypt(Message &res, const Ciphertext &ctxt,
                     const SecretKey &secKey, double scale) {
  Polynomial temp(DEGREE, MOD_Q);

  if (ctxt.getIsNTT()) {
    eval_.mult(temp, ctxt.getA(), secKey.getPolyQ());
  } else {
    eval_.ntt(temp, ctxt.getA());
    eval_.mult(temp, temp, secKey.getPolyQ());
    eval_.intt(temp, temp);
  }
  eval_.add(temp, temp, ctxt.getB());
  if (ctxt.getIsExtended()) {
    if (!ctxt.getIsNTT())
      eval_.ntt(temp, temp);
    eval_.mult(temp, temp, secKey.getPolyQ());
    if (!ctxt.getIsNTT())
      eval_.intt(temp, temp);
    eval_.add(temp, temp, ctxt.getC());
  }
  if (ctxt.getIsNTT())
    eval_.intt(temp, temp);
  decode(res, temp, scale);
}

void Client::encryptQuery(MLWECiphertext &res, const Message &msg,
                          const SecretKey &secKey, double scale) {
  Polynomial ptxt(DEGREE, MOD_Q), temp(DEGREE, MOD_Q);

  encode(ptxt, msg, scale);
  eval_.aut(temp, ptxt, 2 * getRank() - 1, getRank());
  encrypt(res, temp, secKey);
  eval_.mult(res, res, invRank_);
}

void Client::encodeQuery(Polynomial &res, const Message &msg, double scale) {
  Polynomial temp(getRank(), MOD_Q);

  encode(temp, msg, scale);
  eval_.aut(res, temp, 2 * getRank() - 1, getRank());
  eval_.mult(res, res, invRank_);
}

void Client::encryptKey(MLWECiphertext &res, const Message &msg,
                        const SecretKey &secKey, double scale) {
  Polynomial ptxt(DEGREE, MOD_Q);

  encode(ptxt, msg, scale);
  encrypt(res, ptxt, secKey);
  eval_.mult(res, res, invRank_);
}

void Client::encodeKey(Polynomial &res, const Message &msg, double scale) {
  encode(res, msg, scale);
  eval_.mult(res, res, invRank_);
}

void Client::decryptScore(std::vector<Message> &msg,
                          std::vector<Ciphertext> &score,
                          const SecretKey &secretKey, double scale) {
#pragma omp parallel for
  for (u64 i = 0; i < score.size(); ++i)
    decrypt(msg[i], score[i], secretKey, scale);
}

void Client::topKScore(TopK &res, const std::vector<Message> &msg) {
  using Pair = std::pair<double, int>;
  struct Compare {
    bool operator()(const Pair &a, const Pair &b) const noexcept {
      return a.first > b.first;
    }
  };
  std::priority_queue<Pair, std::vector<Pair>, Compare> min_heap;
  for (u64 i = 0; i < msg.size(); ++i) {
    for (u64 j = 0; j < DEGREE; ++j) {
      if (min_heap.size() < res.size())
        min_heap.push(std::make_pair(msg[i][j], i * DEGREE + j));
      else if (min_heap.top().first < msg[i][j]) {
        min_heap.pop();
        min_heap.push(std::make_pair(msg[i][j], i * DEGREE + j));
      }
    }
  }
  for (u64 i = 0; i < res.size(); ++i) {
    res[res.size() - i - 1] = min_heap.top().second;
    min_heap.pop();
  }
}

void Client::encryptPIR(Ciphertext &res, u64 idx, const SecretKey &secKey,
                        double scale) {
  Polynomial ptxt(DEGREE, MOD_Q);

  ptxt[idx] = scale;
  eval_.mult(ptxt, ptxt, invRank_);
  encrypt(res, ptxt, secKey);
}

void Client::encodePIRPayload(Polynomial &res, const unsigned char *payload) {
  constexpr u64 payloadSize = DEGREE / 4;

  res.setIsNTT(false);
  // Each coefficient stores 2 bits
  u64 coeff_idx = 0;
  for (u64 byte_idx = 0; byte_idx < payloadSize; ++byte_idx) {
    unsigned char byte = payload[byte_idx];
    for (int bit_pair = 0; bit_pair < 4; ++bit_pair) {
      u64 two_bits = (byte >> (bit_pair * 2)) & 3; // Extract 2 bits
      res[coeff_idx++] = (two_bits > 1) ? (MOD_Q - two_bits + 1) : two_bits;
    }
  }

  // NTT the polynomial
  eval_.ntt(res, res);
}

void Client::decodePIRPayload(unsigned char *payload, const Message &dmsg) {
  constexpr u64 payloadSize = DEGREE / 4;

  memset(payload, 0, payloadSize);

  u64 coeff_idx = 0;
  for (u64 byte_idx = 0; byte_idx < payloadSize; ++byte_idx) {
    unsigned char byte = 0;
    for (int bit_pair = 0; bit_pair < 4; ++bit_pair) {
      // Round the decrypted value (already scaled by decrypt)
      int rounded = std::round(dmsg[coeff_idx]);
      u64 two_bits;
      switch (rounded) {
      case 0:
        two_bits = 0;
        break;
      case 1:
        two_bits = 1;
        break;
      case -1:
        two_bits = 2;
        break;
      case -2:
        two_bits = 3;
        break;
      default:
        throw std::runtime_error("Invalid rounded value");
      }
      byte |= (two_bits << (bit_pair * 2));
      coeff_idx++;
    }
    payload[byte_idx] = byte;
  }
}

// private

void Client::genSwtKey(SwitchingKey &res, const SecretKey &secKey,
                       const Polynomial &modifiedKey) {
  Polynomial tempModQ(DEGREE, MOD_Q), tempModP(DEGREE, MOD_P);

  Random::sampleUniform(res.getPolyAModQ());
  Random::sampleUniform(res.getPolyAModP());
  eval_.ntt(res.getPolyAModQ(), res.getPolyAModQ());
  eval_.ntt(res.getPolyAModP(), res.getPolyAModP());
  Random::sampleDiscreteGaussian(res.getPolyBModQ(), res.getPolyBModP());
  eval_.ntt(res.getPolyBModQ(), res.getPolyBModQ());
  eval_.ntt(res.getPolyBModP(), res.getPolyBModP());

  eval_.mult(tempModQ, res.getPolyAModQ(), secKey.getPolyQ());
  eval_.sub(res.getPolyBModQ(), res.getPolyBModQ(), tempModQ);
  eval_.mult(tempModP, res.getPolyAModP(), secKey.getPolyP());
  eval_.sub(res.getPolyBModP(), res.getPolyBModP(), tempModP);
  eval_.mad(res.getPolyBModQ(), modifiedKey, P_MOD_Q, res.getPolyBModQ());
}

} // namespace HEVEC
