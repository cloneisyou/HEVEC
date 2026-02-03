#pragma once

#include "Ciphertext.hpp"
#include "Const.hpp"
#include "HEval.hpp"
#include "Keys.hpp"
#include "MLWECiphertext.hpp"
#include "Polynomial.hpp"
#include "SwitchingKey.hpp"

namespace HEVEC {

class CachedQuery {
public:
  CachedQuery(u64 rank) : rank_(rank), ctxts_(rank) {}

  std::vector<Ciphertext> &getCtxts() { return ctxts_; }
  const std::vector<Ciphertext> &getCtxts() const { return ctxts_; }

private:
  const u64 rank_;
  std::vector<Ciphertext> ctxts_;
};

class CachedKeys {
public:
  CachedKeys(u64 rank) : rank_(rank), ctxts_(rank) {}

  std::vector<Ciphertext> &getCtxts() { return ctxts_; }
  const std::vector<Ciphertext> &getCtxts() const { return ctxts_; }

private:
  const u64 rank_;
  std::vector<Ciphertext> ctxts_;
};

class CachedPlaintextQuery {
public:
  CachedPlaintextQuery(u64 rank)
      : rank_(rank), polys_(rank, Polynomial(DEGREE, MOD_Q)) {}

  std::vector<Polynomial> &getPolys() { return polys_; }
  const std::vector<Polynomial> &getPolys() const { return polys_; }

private:
  const u64 rank_;
  std::vector<Polynomial> polys_;
};

class Server {
public:
  Server(u64 logRank, const SwitchingKey &relinKey,
         const AutedModPackKeys &autedModPackKeys,
         const AutedModPackMLWEKeys &autedModPackMLWEKeys);

  void cacheQuery(CachedQuery &res, const MLWECiphertext &query);
  void cacheQuery(CachedPlaintextQuery &res, const Polynomial &query);
  void cacheKeys(CachedKeys &res, const std::vector<MLWECiphertext> &keys);
  void innerProduct(Ciphertext &res, const CachedQuery &cachedQuery,
                    const CachedKeys &cachedKey);
  void innerProduct(Ciphertext &res, const CachedPlaintextQuery &cachedQuery,
                    const CachedKeys &cachedKey);

private:
  const u64 logRank_;
  const u64 rank_;
  const u64 stack_;

  HEval eval_;

  const SwitchingKey &relinKey_;
  const AutedModPackKeys &autedModPackKeys_;
  const AutedModPackMLWEKeys &autedModPackMLWEKeys_;
};
} // namespace HEVEC