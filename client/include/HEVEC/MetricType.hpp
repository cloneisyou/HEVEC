#pragma once

#include "Type.hpp"

namespace HEVEC {
enum class MetricType : u8 {
  IP = 0,
  L2 = 1,
  COSINE = 2,
};
} // namespace HEVEC