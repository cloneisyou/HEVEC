#pragma once

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <limits>
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

class HEVECClient {
public:
  HEVECClient(const std::string &host, const std::string &port);
  ~HEVECClient();

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
  using HttpRequest = boost::beast::http::request<boost::beast::http::vector_body<uint8_t>>;
  using HttpResponse = boost::beast::http::response<boost::beast::http::vector_body<uint8_t>>;

  boost::asio::io_context io_context_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::beast::tcp_stream stream_;
  boost::beast::flat_buffer buffer_;
  std::string host_;
  std::string port_;

  void ensureConnection();
  void closeStream();
  HttpResponse performPost(const std::string &target,
                           std::vector<uint8_t> &&body,
                           bool close = false);
  HttpResponse performDelete(const std::string &target);

  std::unordered_map<std::string, std::unique_ptr<CollectionContext>>
      collections_;
  std::unordered_map<std::string, u64> db_sizes_;
  SecretKey secKey_;
  bool secKeyGenerated_ = false;

  unsigned char aesKey_[AES_KEY_SIZE];
  bool aesKeyGenerated_ = false;
  const std::size_t max_body_size_{std::numeric_limits<std::size_t>::max()};
};

} // namespace HEVEC
