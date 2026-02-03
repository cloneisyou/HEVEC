#pragma once

#include <vector>

#include "Const.hpp"
#include "MLWESwitchingKey.hpp"
#include "SwitchingKey.hpp"

namespace HEVEC {

class AutedModPackKeys {
public:
  AutedModPackKeys(u64 rank)
      : keys_(rank, std::vector<SwitchingKey>(DEGREE / rank)) {}
  std::vector<std::vector<SwitchingKey>> &getKeys() { return keys_; }
  const std::vector<std::vector<SwitchingKey>> &getKeys() const {
    return keys_;
  }

private:
  std::vector<std::vector<SwitchingKey>> keys_;
};

class AutedModPackMLWEKeys {
public:
  AutedModPackMLWEKeys(u64 rank) : keys_(rank) {
    for (u64 i = 0; i < rank; ++i) {
      for (u64 j = 0; j < DEGREE / rank; ++j)
        keys_[i].emplace_back(rank);
    }
  }
  std::vector<std::vector<MLWESwitchingKey>> &getKeys() { return keys_; }
  const std::vector<std::vector<MLWESwitchingKey>> &getKeys() const {
    return keys_;
  }

private:
  std::vector<std::vector<MLWESwitchingKey>> keys_;
};

class InvAutKeys {
public:
  InvAutKeys(u64 rank) : keys_(rank) {}
  std::vector<SwitchingKey> &getKeys() { return keys_; }
  const std::vector<SwitchingKey> &getKeys() const { return keys_; }

private:
  std::vector<SwitchingKey> keys_;
};

} // namespace HEVEC
