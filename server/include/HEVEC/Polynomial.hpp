#pragma once

#include <vector>

#include "Type.hpp"

namespace HEVEC {

class Polynomial {
public:
  explicit Polynomial(u64 degree, u64 mod)
      : is_ntt_(false), mod_(mod), data_(degree, 0) {}

  // Rule of Five
  Polynomial(const Polynomial &other) = default;
  Polynomial(Polynomial &&other) noexcept = default;
  Polynomial &operator=(const Polynomial &other) = default;
  Polynomial &operator=(Polynomial &&other) noexcept = default;

  void setIsNTT(bool is_ntt) { is_ntt_ = is_ntt; }
  bool getIsNTT() const { return is_ntt_; }

  u64 *getData() { return data_.data(); }
  const u64 *getData() const { return data_.data(); }
  u64 getMod() const { return mod_; }
  u64 getDegree() const { return data_.size(); }

  u64 &operator[](u64 i) { return data_[i]; }
  const u64 &operator[](u64 i) const { return data_[i]; }

private:
  bool is_ntt_;
  u64 mod_;
  std::vector<u64> data_;
};
} // namespace HEVEC