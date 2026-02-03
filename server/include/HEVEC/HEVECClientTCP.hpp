#pragma once

#include <asio.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "MetricType.hpp"
#include "SecretKey.hpp"
#include "TopK.hpp"
#include "Type.hpp"

namespace HEVEC {

// PIR-specific constants from ex5-pir.cpp
constexpr u64 PIR_LOG_RANK = 10;
constexpr u64 PIR_RANK = 1ULL << PIR_LOG_RANK;
constexpr double PIR_FIRST_SCALE = 25.25;
constexpr double PIR_SECOND_SCALE = 25.25;

class HEVECClientTCP {
public:
  HEVECClientTCP(const std::string &host, const std::string &port);
  ~HEVECClientTCP();

  u64 setupCollection(const std::string &collectionName, u64 dimension,
                      const std::string &metric_type,
                      bool is_query_encrypt = true);

  void dropCollection(const std::string &collectionName);

  void terminate();

  void insert(const std::string &collectionName,
              const std::vector<std::vector<float>> &db,
              const std::vector<std::string> &payloads);

  std::vector<float> query(const std::string &collectionName,
                           const std::vector<float> &query_vec);

  void queryAndTopK(TopK &res, const std::string &collectionName,
                    const std::vector<float> &query_vec);

  void queryAndTopKWithScores(std::vector<std::pair<u64, float>> &res,
                              const std::string &collectionName,
                              const std::vector<float> &query_vec, u64 k);

  static std::vector<u64> getTopKIndices(const std::vector<float> &scores,
                                         u64 k);

  std::string retrieve(const std::string &collectionName, u64 index);

  std::string retrievePIR(const std::string &collectionName, u64 index);

private:
  struct CollectionContext;
  asio::io_context io_context_;
  asio::ip::tcp::socket socket_;
  std::unordered_map<std::string, std::unique_ptr<CollectionContext>>
      collections_;
  std::unordered_map<std::string, u64> db_sizes_;
  SecretKey secKey_;
  bool secKeyGenerated_ = false;

  unsigned char aesKey_[AES_KEY_SIZE];
  bool aesKeyGenerated_ = false;
};

} // namespace HEVEC
