#pragma once

#include <utility>
#include <vector>

#include "Const.hpp"
#include "Polynomial.hpp"

namespace HEVEC {
class MLWECiphertext {
public:
  explicit MLWECiphertext(u64 rank)
      : rank_(rank), stack_(DEGREE / rank),
        polys_(DEGREE / rank + 1, Polynomial(rank, MOD_Q)) {}

  // Rule of Five: Explicitly defined
  MLWECiphertext(const MLWECiphertext &other)
      : rank_(other.rank_), stack_(other.stack_), polys_(other.polys_) {}

  MLWECiphertext(MLWECiphertext &&other) noexcept
      : rank_(other.rank_), stack_(other.stack_),
        polys_(std::move(other.polys_)) {}

  MLWECiphertext &operator=(const MLWECiphertext &other) {
    if (this != &other) {
      rank_ = other.rank_;
      stack_ = other.stack_;
      polys_ = other.polys_;
    }
    return *this;
  }

  MLWECiphertext &operator=(MLWECiphertext &&other) noexcept {
    if (this != &other) {
      rank_ = other.rank_;
      stack_ = other.stack_;
      polys_ = std::move(other.polys_);
    }
    return *this;
  }

  Polynomial &getA(u64 index) { return polys_[index]; }
  const Polynomial &getA(u64 index) const { return polys_[index]; }

  Polynomial &getB() { return polys_[stack_]; }
  const Polynomial &getB() const { return polys_[stack_]; }

  u64 getRank() const { return rank_; }
  u64 getStack() const { return stack_; }
  u64 getDegree() const { return DEGREE; }

private:
  u64 rank_;
  u64 stack_;
  std::vector<Polynomial> polys_;
};
} // namespace HEVEC