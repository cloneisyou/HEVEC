#include "HEVEC/HEVECClient.hpp"

#include <algorithm>
#include <cstdint>
#include <boost/asio/connect.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <queue>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Client.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/Message.hpp"
#include "HEVEC/MetricType.hpp"
#include "HEVEC/TopK.hpp"

namespace HEVEC {

namespace {

namespace http = boost::beast::http;

void logToFile(const std::string &message) {
  const char *log_path_env = std::getenv("HEVEC_CLIENT_LOG_PATH");
  if (log_path_env) {
    std::ofstream log_file(log_path_env, std::ios::app);
    if (log_file.is_open()) {
      auto now = std::chrono::system_clock::now();
      auto time_t = std::chrono::system_clock::to_time_t(now);
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) %
                1000;

      log_file << "["
               << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
      log_file << "." << std::setfill('0') << std::setw(3) << ms.count()
               << "] ";
      log_file << message << std::endl;
      log_file.close();
    }
  }
}

void handleOpenSslErrors() {
  ERR_print_errors_fp(stderr);
  throw std::runtime_error("OpenSSL error");
}

void generateIvFromIndex(unsigned char *iv, HEVEC::u64 index) {
  memset(iv, 0, AES_BLOCK_SIZE);
  memcpy(iv, &index, sizeof(HEVEC::u64));
}

void encryptPayload(const std::string &plaintext, std::string &ciphertext,
                     const unsigned char *key, HEVEC::u64 index) {
  if (plaintext.size() > PIR_PAYLOAD_SIZE) {
    throw std::invalid_argument("Payload size cannot exceed " +
                                std::to_string(PIR_PAYLOAD_SIZE) + " bytes");
  }

  std::vector<unsigned char> ptxt(PIR_PAYLOAD_SIZE, 0);
  memcpy(ptxt.data(), plaintext.data(), plaintext.size());

  unsigned char iv[AES_BLOCK_SIZE];
  generateIvFromIndex(iv, index);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handleOpenSslErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    handleOpenSslErrors();
  }

  ciphertext.resize(PIR_PAYLOAD_SIZE);
  int len;
  int ciphertext_len = 0;

  if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)ciphertext.data(), &len,
                             ptxt.data(), ptxt.size())) {
    EVP_CIPHER_CTX_free(ctx);
    handleOpenSslErrors();
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)ciphertext.data() + len,
                               &len)) {
    EVP_CIPHER_CTX_free(ctx);
    handleOpenSslErrors();
  }
  ciphertext_len += len;

  if (ciphertext_len != PIR_PAYLOAD_SIZE) {
    throw std::runtime_error("Encryption output size is not " +
                             std::to_string(PIR_PAYLOAD_SIZE) + " bytes");
  }

  EVP_CIPHER_CTX_free(ctx);
}

void decryptPayload(const std::string &ciphertext, std::string &plaintext,
                     const unsigned char *key, HEVEC::u64 index) {
  if (ciphertext.size() != PIR_PAYLOAD_SIZE) {
    throw std::invalid_argument("Ciphertext size must be " +
                                std::to_string(PIR_PAYLOAD_SIZE) + " bytes");
  }

  unsigned char iv[AES_BLOCK_SIZE];
  generateIvFromIndex(iv, index);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handleOpenSslErrors();

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    handleOpenSslErrors();
  }

  plaintext.resize(PIR_PAYLOAD_SIZE);
  int len;
  int plaintext_len = 0;

  if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)plaintext.data(), &len,
                             (const unsigned char *)ciphertext.data(),
                             ciphertext.size())) {
    EVP_CIPHER_CTX_free(ctx);
    handleOpenSslErrors();
  }
  plaintext_len = len;

  if (1 !=
      EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext.data() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    handleOpenSslErrors();
  }
  plaintext_len += len;

  plaintext.resize(plaintext_len);

  size_t end = plaintext.find('\0');
  if (end != std::string::npos) {
    plaintext.resize(end);
  }

  EVP_CIPHER_CTX_free(ctx);
}

bool generateAesKey(unsigned char *key) {
  return RAND_bytes(key, AES_KEY_SIZE) == 1;
}

bool saveAesKey(const std::string &path, const unsigned char *key) {
  std::ofstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  file.write(reinterpret_cast<const char *>(key), AES_KEY_SIZE);
  return file.good();
}

bool loadAesKey(const std::string &path, unsigned char *key) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  file.read(reinterpret_cast<char *>(key), AES_KEY_SIZE);
  return file.gcount() == AES_KEY_SIZE;
}

struct BinaryReader {
  const std::vector<uint8_t> &buffer;
  std::size_t pos{0};

  explicit BinaryReader(const std::vector<uint8_t> &buf) : buffer(buf) {}

  template <typename T> bool read(T &value) {
    if (pos + sizeof(T) > buffer.size()) {
      return false;
    }
    std::memcpy(&value, buffer.data() + pos, sizeof(T));
    pos += sizeof(T);
    return true;
  }

  bool readBytes(void *dest, std::size_t len) {
    if (pos + len > buffer.size()) {
      return false;
    }
    std::memcpy(dest, buffer.data() + pos, len);
    pos += len;
    return true;
  }
};

template <typename T>
void appendBinary(std::vector<uint8_t> &out, const T &value) {
  const auto *ptr = reinterpret_cast<const uint8_t *>(&value);
  out.insert(out.end(), ptr, ptr + sizeof(T));
}

inline void appendBinary(std::vector<uint8_t> &out, const void *data,
                         std::size_t len) {
  const auto *ptr = static_cast<const uint8_t *>(data);
  out.insert(out.end(), ptr, ptr + len);
}

std::string vectorToString(const std::vector<uint8_t> &data) {
  return std::string(data.begin(), data.end());
}

} // namespace

struct HEVECClient::CollectionContext {
  u64 dimension;
  u64 log_rank;
  u64 rank;
  u64 stack;
  MetricType metric_type;
  std::unique_ptr<Client> client;
  std::unique_ptr<Client> pirClient;
  SwitchingKey relinKey;
  AutedModPackKeys autedModPackKeys;
  AutedModPackMLWEKeys autedModPackMLWEKeys;

  // PIR-specific keys
  InvAutKeys pirInvAutKeys;

  // Scales
  double queryScale;
  double keyScale;
  double outputScale;

  bool isQueryEncrypt;

  CollectionContext(u64 dim, MetricType mt, bool is_encrypt)
      : dimension(dim), log_rank(static_cast<u64>(std::ceil(std::log2(dim)))),
        rank(1ULL << log_rank), stack(DEGREE / rank), metric_type(mt),
        client(std::make_unique<Client>(log_rank)),
        pirClient(std::make_unique<Client>(PIR_LOG_RANK)),
        autedModPackKeys(rank), autedModPackMLWEKeys(rank),
        pirInvAutKeys(PIR_RANK), isQueryEncrypt(is_encrypt) {
    if (metric_type == MetricType::IP) {
      if (is_encrypt) {
        queryScale = std::pow(2.0, 22);
        keyScale = std::pow(2.0, 22);
      } else {
        queryScale = std::pow(2.0, 16);
        keyScale = std::pow(2.0, 27);
      }
    } else if (metric_type == MetricType::COSINE) {
      if (is_encrypt) {
        queryScale = std::pow(2.0, 26.25);
        keyScale = std::pow(2.0, 26.25);
      } else {
        queryScale = std::pow(2.0, 20);
        keyScale = std::pow(2.0, 32.5);
      }
    }
    outputScale = queryScale * keyScale;
  }
};

MetricType stringToMetricType(const std::string &s) {
  if (s == "IP")
    return MetricType::IP;
  if (s == "COSINE")
    return MetricType::COSINE;
  throw std::invalid_argument("Unsupported metric type: " + s);
}

HEVECClient::HEVECClient(const std::string &host, const std::string &port)
    : resolver_(io_context_), stream_(io_context_), host_(host), port_(port) {
  ensureConnection();

  const char *sec_key_path_env = std::getenv("HEVEC_SEC_KEY_PATH");
  std::string sec_key_path =
      sec_key_path_env ? std::string(sec_key_path_env) : "";

  if (!sec_key_path.empty()) {
    if (secKey_.load(sec_key_path)) {
      logToFile("Loaded secret key from " + sec_key_path);
      secKeyGenerated_ = true;
    }
  }

  const char *aes_key_path_env = std::getenv("HEVEC_AES_KEY_PATH");
  std::string aes_key_path =
      aes_key_path_env ? std::string(aes_key_path_env) : "";

  if (!aes_key_path.empty()) {
    if (loadAesKey(aes_key_path, aesKey_)) {
      logToFile("Loaded AES key from " + aes_key_path);
      aesKeyGenerated_ = true;
    }
  }

  if (!aesKeyGenerated_) {
    generateAesKey(aesKey_);
    aesKeyGenerated_ = true;
    logToFile("Generated new AES key.");
    if (!aes_key_path.empty()) {
      if (saveAesKey(aes_key_path, aesKey_)) {
        logToFile("Saved new AES key to " + aes_key_path);
      } else {
        std::cerr << "Failed to save AES key to " << aes_key_path << std::endl;
      }
    }
  }
}

HEVECClient::~HEVECClient() {
  try {
    terminate();
  } catch (const std::exception &e) {
    std::cerr << "Error during client termination: " << e.what() << std::endl;
  }
}

void HEVECClient::ensureConnection() {
  if (stream_.socket().is_open()) {
    return;
  }
  auto endpoints = resolver_.resolve(host_, port_);
  stream_.connect(endpoints);
}

void HEVECClient::closeStream() {
  boost::beast::error_code ec;
  if (stream_.socket().is_open()) {
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    stream_.socket().close(ec);
  }
  buffer_.consume(buffer_.size());
}

HEVECClient::HttpResponse
HEVECClient::performPost(const std::string &target, std::vector<uint8_t> &&body,
                       bool close) {
  ensureConnection();

  HttpRequest req{http::verb::post, target, 11};
  req.set(http::field::host, host_);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.set(http::field::content_type, "application/octet-stream");
  if (close) {
    req.set(http::field::connection, "close");
  }
  req.body() = std::move(body);
  req.prepare_payload();

  http::write(stream_, req);

  http::response_parser<HttpResponse::body_type> parser;
  parser.body_limit(static_cast<std::uint64_t>(max_body_size_));
  try {
    http::read(stream_, buffer_, parser);
  } catch (const boost::system::system_error &err) {
    closeStream();
    throw std::runtime_error(std::string("HTTP POST ") + target +
                             " failed: " + err.code().message());
  }
  HttpResponse res = parser.release();
  buffer_.consume(buffer_.size());

  if (close || res.need_eof()) {
    closeStream();
  }

  if (res.result() != http::status::ok) {
    closeStream();
    throw std::runtime_error("HTTP POST " + target +
                             " failed: " + vectorToString(res.body()));
  }

  return res;
}

HEVECClient::HttpResponse HEVECClient::performDelete(const std::string &target) {
  ensureConnection();

  HttpRequest req{http::verb::delete_, target, 11};
  req.set(http::field::host, host_);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.body() = {};
  req.prepare_payload();
  req.content_length(0);

  http::write(stream_, req);

  http::response_parser<HttpResponse::body_type> parser;
  parser.body_limit(static_cast<std::uint64_t>(max_body_size_));
  try {
    http::read(stream_, buffer_, parser);
  } catch (const boost::system::system_error &err) {
    closeStream();
    throw std::runtime_error(std::string("HTTP DELETE ") + target +
                             " failed: " + err.code().message());
  }
  HttpResponse res = parser.release();
  buffer_.consume(buffer_.size());

  if (res.need_eof()) {
    closeStream();
  }

  if (res.result() != http::status::ok) {
    closeStream();
    throw std::runtime_error("HTTP DELETE " + target +
                             " failed: " + vectorToString(res.body()));
  }

  return res;
}

u64 HEVECClient::setupCollection(const std::string &collectionName, u64 dimension,
                               const std::string &metric_type_str,
                               bool is_query_encrypt) {
  if (dimension == 0 || dimension > DEGREE) {
    throw std::invalid_argument("Dimension must be between 1 and " +
                                std::to_string(DEGREE));
  }

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  MetricType metric_type = stringToMetricType(metric_type_str);

  std::vector<uint8_t> body;
  appendBinary(body, collectionHash);
  appendBinary(body, dimension);
  appendBinary(body, metric_type);
  uint8_t has_keys = 0;
  appendBinary(body, has_keys);

  auto response = performPost("/collections/setup", std::move(body));
  BinaryReader reader(response.body());

  uint8_t setup_status = 0;
  u64 server_dimension = 0;
  MetricType server_metric_type = metric_type;
  u64 server_db_size = 0;

  if (!reader.read(setup_status) || !reader.read(server_dimension) ||
      !reader.read(server_metric_type) || !reader.read(server_db_size)) {
    throw std::runtime_error("Malformed setup response from server");
  }

  if (setup_status == 2) {
    throw std::runtime_error("Failed to setup collection '" + collectionName +
                             "': Dimension mismatch with server.");
  }

  if (setup_status == 0) {
    if (!collections_.count(collectionName)) {
      collections_[collectionName] = std::make_unique<CollectionContext>(
          server_dimension, server_metric_type, is_query_encrypt);
    }
    db_sizes_[collectionName] = server_db_size;
    logToFile("Collection '" + collectionName +
              "' ready on server with size " +
              std::to_string(server_db_size) + ". Setup complete.");
    return server_db_size;
  }

  if (setup_status != 1) {
    throw std::runtime_error("Unexpected setup status from server");
  }

  if (!collections_.count(collectionName)) {
    collections_[collectionName] = std::make_unique<CollectionContext>(
        dimension, metric_type, is_query_encrypt);
    db_sizes_[collectionName] = 0;
  }

  auto &ctx = collections_.at(collectionName);

  if (!secKeyGenerated_) {
    ctx->client->genSecKey(secKey_);
    secKeyGenerated_ = true;
    const char *sec_key_path_env = std::getenv("HEVEC_SEC_KEY_PATH");
    if (sec_key_path_env) {
      std::string sec_key_path(sec_key_path_env);
      if (secKey_.save(sec_key_path)) {
        logToFile("Saved new secret key to " + sec_key_path);
      } else {
        std::cerr << "Failed to save secret key to " << sec_key_path
                  << std::endl;
      }
    }
  }
  ctx->client->genRelinKey(ctx->relinKey, secKey_);
  ctx->client->genAutedModPackKeys(ctx->autedModPackKeys, secKey_);
  ctx->client->genInvAutedModPackKeys(ctx->autedModPackMLWEKeys, secKey_);

  ctx->pirClient->genInvAutKeys(ctx->pirInvAutKeys.getKeys(), secKey_,
                                PIR_RANK);

  logToFile("Collection '" + collectionName + "' is new. Sending keys...");

  std::vector<uint8_t> key_body;
  appendBinary(key_body, collectionHash);
  appendBinary(key_body, dimension);
  appendBinary(key_body, metric_type);
  has_keys = 1;
  appendBinary(key_body, has_keys);

  appendBinary(key_body, ctx->relinKey.getPolyAModQ().getData(),
               DEGREE * sizeof(u64));
  appendBinary(key_body, ctx->relinKey.getPolyAModP().getData(),
               DEGREE * sizeof(u64));
  appendBinary(key_body, ctx->relinKey.getPolyBModQ().getData(),
               DEGREE * sizeof(u64));
  appendBinary(key_body, ctx->relinKey.getPolyBModP().getData(),
               DEGREE * sizeof(u64));

  for (u64 i = 0; i < ctx->rank; ++i) {
    for (u64 j = 0; j < ctx->stack; ++j) {
      auto &key = ctx->autedModPackKeys.getKeys()[i][j];
      appendBinary(key_body, key.getPolyAModQ().getData(),
                   DEGREE * sizeof(u64));
      appendBinary(key_body, key.getPolyAModP().getData(),
                   DEGREE * sizeof(u64));
      appendBinary(key_body, key.getPolyBModQ().getData(),
                   DEGREE * sizeof(u64));
      appendBinary(key_body, key.getPolyBModP().getData(),
                   DEGREE * sizeof(u64));
    }
  }

  for (u64 i = 0; i < ctx->rank; ++i) {
    for (u64 j = 0; j < ctx->stack; ++j) {
      auto &key = ctx->autedModPackMLWEKeys.getKeys()[i][j];
      for (u64 k = 0; k < ctx->stack; ++k) {
        appendBinary(key_body, key.getPolyAModQ(k).getData(),
                     ctx->rank * sizeof(u64));
        appendBinary(key_body, key.getPolyAModP(k).getData(),
                     ctx->rank * sizeof(u64));
        appendBinary(key_body, key.getPolyBModQ(k).getData(),
                     ctx->rank * sizeof(u64));
        appendBinary(key_body, key.getPolyBModP(k).getData(),
                     ctx->rank * sizeof(u64));
      }
    }
  }

  for (u64 i = 0; i < PIR_RANK; ++i) {
    auto &key = ctx->pirInvAutKeys.getKeys()[i];
    appendBinary(key_body, key.getPolyAModQ().getData(),
                 DEGREE * sizeof(u64));
    appendBinary(key_body, key.getPolyAModP().getData(),
                 DEGREE * sizeof(u64));
    appendBinary(key_body, key.getPolyBModQ().getData(),
                 DEGREE * sizeof(u64));
    appendBinary(key_body, key.getPolyBModP().getData(),
                 DEGREE * sizeof(u64));
  }

  auto final_response =
      performPost("/collections/setup", std::move(key_body));
  BinaryReader final_reader(final_response.body());

  uint8_t final_status = 0;
  u64 final_dimension = 0;
  MetricType final_metric_type = metric_type;
  u64 final_db_size = 0;

  if (!final_reader.read(final_status) ||
      !final_reader.read(final_dimension) ||
      !final_reader.read(final_metric_type) ||
      !final_reader.read(final_db_size)) {
    throw std::runtime_error("Malformed setup confirmation from server");
  }

  if (final_status == 2) {
    throw std::runtime_error("Server reported dimension mismatch after key "
                             "upload for collection '" +
                             collectionName + "'");
  }

  if (final_status != 0) {
    throw std::runtime_error("Unexpected setup confirmation status");
  }

  db_sizes_[collectionName] = final_db_size;
  logToFile("Collection '" + collectionName + "' registered on server.");

  return final_db_size;
}


void HEVECClient::terminate() {
  try {
    performPost("/terminate", {}, true);
  } catch (const std::exception &) {
    boost::beast::error_code ec;
    if (stream_.socket().is_open()) {
      stream_.socket().close(ec);
    }
  }
}


void HEVECClient::dropCollection(const std::string &collectionName) {
  u64 collectionHash = std::hash<std::string>{}(collectionName);
  performDelete("/collections/" + std::to_string(collectionHash));

  collections_.erase(collectionName);
  db_sizes_.erase(collectionName);

  logToFile("Dropped collection '" + collectionName + "'");
}


void HEVECClient::insert(const std::string &collectionName,
                       const std::vector<std::vector<float>> &db,
                       const std::vector<std::string> &payloads) {
  if (db.empty()) {
    return;
  }
  if (db.size() != payloads.size()) {
    throw std::invalid_argument(
        "Database and payloads must have the same size.");
  }
  if (db[0].empty()) {
    throw std::invalid_argument("Database vectors cannot be empty.");
  }
  if (!collections_.count(collectionName)) {
    throw std::invalid_argument("Collection " + collectionName +
                                " does not exist. Call setupCollection first.");
  }
  auto &ctx = collections_.at(collectionName);
  if (db[0].size() > ctx->rank) {
    throw std::invalid_argument(
        "Vector dimension " + std::to_string(db[0].size()) +
        " exceeds collection capacity " + std::to_string(ctx->rank));
  }

  auto whole_start = std::chrono::high_resolution_clock::now();

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  u64 num_to_insert = db.size();

  std::vector<uint8_t> body;
  body.reserve(sizeof(collectionHash) + sizeof(num_to_insert) +
               num_to_insert * (ctx->stack * ctx->rank * sizeof(u64) +
                                ctx->rank * sizeof(u64) + PIR_PAYLOAD_SIZE));
  appendBinary(body, collectionHash);
  appendBinary(body, num_to_insert);

  u64 current_db_size = db_sizes_.at(collectionName);
  std::string aes_payload(PIR_PAYLOAD_SIZE, '\0');

  for (size_t i = 0; i < db.size(); ++i) {
    const auto &vec = db[i];
    Message msg(ctx->rank);
    for (u64 k = 0; k < vec.size(); ++k)
      msg[k] = vec[k];

    MLWECiphertext key_to_send(ctx->rank);
    ctx->client->encryptKey(key_to_send, msg, secKey_, ctx->keyScale);

    for (u64 k = 0; k < ctx->stack; ++k) {
      appendBinary(body, key_to_send.getA(k).getData(),
                   ctx->rank * sizeof(u64));
    }
    appendBinary(body, key_to_send.getB().getData(),
                 ctx->rank * sizeof(u64));

    u64 global_idx = current_db_size + i;
    encryptPayload(payloads[i], aes_payload, aesKey_, global_idx);
    appendBinary(body, aes_payload.data(), PIR_PAYLOAD_SIZE);
  }

  performPost("/collections/insert", std::move(body));

  db_sizes_.at(collectionName) += num_to_insert;
  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);
  logToFile("Sent " + std::to_string(num_to_insert) +
            " keys to server. Total time: " +
            std::to_string(whole_duration.count()) + "ms");
}


std::vector<float> HEVECClient::query(const std::string &collectionName,
                                    const std::vector<float> &query_vec) {
  if (!collections_.count(collectionName)) {
    u64 dimension = query_vec.size();
    setupCollection(collectionName, dimension, "COSINE", true);
  }
  auto &ctx = collections_.at(collectionName);
  if (db_sizes_.at(collectionName) == 0) {
    throw std::logic_error("DB in collection " + collectionName +
                           " is empty. Call insert first.");
  }
  if (query_vec.size() > ctx->rank) {
    throw std::invalid_argument(
        "Query dimension " + std::to_string(query_vec.size()) +
        " exceeds collection capacity " + std::to_string(ctx->rank));
  }

  auto whole_start = std::chrono::high_resolution_clock::now();

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  const u64 iter = (db_sizes_.at(collectionName) + DEGREE - 1) / DEGREE;

  Message msg(ctx->rank);
  for (u64 j = 0; j < query_vec.size(); ++j)
    msg[j] = query_vec[j];

  std::vector<uint8_t> request_body;
  appendBinary(request_body, collectionHash);

  auto start_enc = std::chrono::high_resolution_clock::now();

  if (ctx->isQueryEncrypt) {
    MLWECiphertext query(ctx->rank);
    ctx->client->encryptQuery(query, msg, secKey_, ctx->queryScale);

    for (u64 i = 0; i < ctx->stack; ++i) {
      appendBinary(request_body, query.getA(i).getData(),
                   ctx->rank * sizeof(u64));
    }
    appendBinary(request_body, query.getB().getData(),
                 ctx->rank * sizeof(u64));
  } else {
    Polynomial query(ctx->rank, MOD_Q);
    ctx->client->encodeQuery(query, msg, ctx->queryScale);
    appendBinary(request_body, query.getData(), ctx->rank * sizeof(u64));
  }

  auto end_enc = std::chrono::high_resolution_clock::now();
  auto duration_enc = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_enc - start_enc);
  logToFile("Encrypt/Encode query: " + std::to_string(duration_enc.count()) +
            "ms");

  auto start_rt = std::chrono::high_resolution_clock::now();
  const char *endpoint =
      ctx->isQueryEncrypt ? "/collections/query" : "/collections/query_ptxt";
  auto response = performPost(endpoint, std::move(request_body));
  auto end_rt = std::chrono::high_resolution_clock::now();
  auto duration_rt = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_rt - start_rt);

  std::vector<Ciphertext> ret(iter);
  std::vector<Message> dmsg;
  dmsg.reserve(iter);
  for (u64 j = 0; j < iter; ++j)
    dmsg.emplace_back(DEGREE);

  BinaryReader reader(response.body());
  for (u64 i = 0; i < iter; ++i) {
    if (!reader.readBytes(ret[i].getA().getData(), DEGREE * sizeof(u64)) ||
        !reader.readBytes(ret[i].getB().getData(), DEGREE * sizeof(u64))) {
      throw std::runtime_error("Malformed query response from server");
    }
    ret[i].getA().setIsNTT(true);
    ret[i].getB().setIsNTT(true);
  }
  logToFile("Query round trip: " + std::to_string(duration_rt.count()) +
            "ms");

  auto start_dec = std::chrono::high_resolution_clock::now();
  ctx->client->decryptScore(dmsg, ret, secKey_, ctx->outputScale);
  auto end_dec = std::chrono::high_resolution_clock::now();
  auto duration_dec = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_dec - start_dec);
  logToFile("Decrypt score: " + std::to_string(duration_dec.count()) + "ms");

  std::vector<float> results;
  results.reserve(db_sizes_.at(collectionName));
  for (u64 j = 0; j < iter; ++j) {
    for (u64 k = 0; k < DEGREE; ++k) {
      if (j * DEGREE + k < db_sizes_.at(collectionName)) {
        results.push_back(dmsg[j][k]);
      }
    }
  }

  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);
  logToFile("Total query time: " + std::to_string(whole_duration.count()) +
            "ms");
  return results;
}


void HEVECClient::queryAndTopK(TopK &res, const std::string &collectionName,
                             const std::vector<float> &query_vec) {
  if (!collections_.count(collectionName)) {
    u64 dimension = query_vec.size();
    setupCollection(collectionName, dimension, "COSINE", true);
  }
  auto &ctx = collections_.at(collectionName);
  const u64 db_size = db_sizes_.at(collectionName);
  const u64 k = res.size();

  if (db_size == 0 || k == 0) {
    return;
  }

  if (query_vec.size() > ctx->rank) {
    throw std::invalid_argument(
        "Query dimension " + std::to_string(query_vec.size()) +
        " exceeds collection capacity " + std::to_string(ctx->rank));
  }

  auto whole_start = std::chrono::high_resolution_clock::now();

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  const u64 iter = (db_size + DEGREE - 1) / DEGREE;

  Message msg(ctx->rank);
  for (u64 j = 0; j < query_vec.size(); ++j)
    msg[j] = query_vec[j];

  std::vector<uint8_t> request_body;
  appendBinary(request_body, collectionHash);

  auto start_enc = std::chrono::high_resolution_clock::now();

  if (ctx->isQueryEncrypt) {
    MLWECiphertext query(ctx->rank);
    ctx->client->encryptQuery(query, msg, secKey_, ctx->queryScale);
    for (u64 i = 0; i < ctx->stack; ++i) {
      appendBinary(request_body, query.getA(i).getData(),
                   ctx->rank * sizeof(u64));
    }
    appendBinary(request_body, query.getB().getData(),
                 ctx->rank * sizeof(u64));
  } else {
    Polynomial query(ctx->rank, MOD_Q);
    ctx->client->encodeQuery(query, msg, ctx->queryScale);
    appendBinary(request_body, query.getData(), ctx->rank * sizeof(u64));
  }

  auto end_enc = std::chrono::high_resolution_clock::now();
  auto duration_enc = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_enc - start_enc);
  logToFile("Encrypt/Encode query: " + std::to_string(duration_enc.count()) +
            "ms");

  const char *endpoint =
      ctx->isQueryEncrypt ? "/collections/query" : "/collections/query_ptxt";
  auto start_rt = std::chrono::high_resolution_clock::now();
  auto response = performPost(endpoint, std::move(request_body));
  auto end_rt = std::chrono::high_resolution_clock::now();
  auto duration_rt = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_rt - start_rt);

  std::vector<Ciphertext> ret(iter);
  BinaryReader reader(response.body());
  for (u64 i = 0; i < iter; ++i) {
    if (!reader.readBytes(ret[i].getA().getData(), DEGREE * sizeof(u64)) ||
        !reader.readBytes(ret[i].getB().getData(), DEGREE * sizeof(u64))) {
      throw std::runtime_error("Malformed query response from server");
    }
    ret[i].getA().setIsNTT(true);
    ret[i].getB().setIsNTT(true);
  }
  logToFile("Query round trip: " + std::to_string(duration_rt.count()) +
            "ms");

  std::vector<Message> dmsg;
  dmsg.reserve(iter);
  for (u64 j = 0; j < iter; ++j)
    dmsg.emplace_back(DEGREE);

  auto start_decrypt = std::chrono::high_resolution_clock::now();
  ctx->client->decryptScore(dmsg, ret, secKey_, ctx->outputScale);
  auto end_decrypt = std::chrono::high_resolution_clock::now();
  auto duration_decrypt = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_decrypt - start_decrypt);
  logToFile("Decrypt score: " + std::to_string(duration_decrypt.count()) +
            "ms");

  auto start_topk = std::chrono::high_resolution_clock::now();

  using Pair = std::pair<double, u64>;
  struct Compare {
    bool operator()(const Pair &a, const Pair &b) const noexcept {
      return a.first > b.first;
    }
  };
  std::priority_queue<Pair, std::vector<Pair>, Compare> min_heap;

  for (u64 i = 0; i < iter; ++i) {
    for (u64 j = 0; j < DEGREE; ++j) {
      u64 global_idx = i * DEGREE + j;
      if (global_idx >= db_size)
        break;

      double score = dmsg[i][j];

      if (min_heap.size() < k) {
        min_heap.push({score, global_idx});
      } else if (min_heap.top().first < score) {
        min_heap.pop();
        min_heap.push({score, global_idx});
      }
    }
  }

  for (u64 i = 0; i < res.size(); ++i) {
    res[res.size() - 1 - i] = min_heap.top().second;
    min_heap.pop();
  }

  auto end_topk = std::chrono::high_resolution_clock::now();
  auto duration_topk = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_topk - start_topk);
  logToFile("Top-K calculation: " + std::to_string(duration_topk.count()) +
            "ms");

  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);
  logToFile("Total queryAndTopK time: " +
            std::to_string(whole_duration.count()) + "ms");
}


void HEVECClient::queryAndTopKWithScores(std::vector<std::pair<u64, float>> &res,
                                       const std::string &collectionName,
                                       const std::vector<float> &query_vec,
                                       u64 k) {
  if (!collections_.count(collectionName)) {
    u64 dimension = query_vec.size();
    setupCollection(collectionName, dimension, "COSINE", true);
  }
  auto &ctx = collections_.at(collectionName);
  const u64 db_size = db_sizes_.at(collectionName);

  if (db_size == 0 || k == 0) {
    res.clear();
    return;
  }

  if (query_vec.size() > ctx->rank) {
    throw std::invalid_argument(
        "Query dimension " + std::to_string(query_vec.size()) +
        " exceeds collection capacity " + std::to_string(ctx->rank));
  }

  auto whole_start = std::chrono::high_resolution_clock::now();

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  const u64 iter = (db_size + DEGREE - 1) / DEGREE;

  Message msg(ctx->rank);
  for (u64 j = 0; j < query_vec.size(); ++j)
    msg[j] = query_vec[j];

  std::vector<uint8_t> request_body;
  appendBinary(request_body, collectionHash);

  auto start_enc = std::chrono::high_resolution_clock::now();

  if (ctx->isQueryEncrypt) {
    MLWECiphertext query(ctx->rank);
    ctx->client->encryptQuery(query, msg, secKey_, ctx->queryScale);
    for (u64 i = 0; i < ctx->stack; ++i) {
      appendBinary(request_body, query.getA(i).getData(),
                   ctx->rank * sizeof(u64));
    }
    appendBinary(request_body, query.getB().getData(),
                 ctx->rank * sizeof(u64));
  } else {
    Polynomial query(ctx->rank, MOD_Q);
    ctx->client->encodeQuery(query, msg, ctx->queryScale);
    appendBinary(request_body, query.getData(), ctx->rank * sizeof(u64));
  }

  auto end_enc = std::chrono::high_resolution_clock::now();
  auto duration_enc = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_enc - start_enc);
  logToFile("Encrypt/Encode query: " + std::to_string(duration_enc.count()) +
            "ms");

  const char *endpoint =
      ctx->isQueryEncrypt ? "/collections/query" : "/collections/query_ptxt";
  auto start_rt = std::chrono::high_resolution_clock::now();
  auto response = performPost(endpoint, std::move(request_body));
  auto end_rt = std::chrono::high_resolution_clock::now();
  auto duration_rt = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_rt - start_rt);

  std::vector<Ciphertext> ret(iter);
  BinaryReader reader(response.body());
  for (u64 i = 0; i < iter; ++i) {
    if (!reader.readBytes(ret[i].getA().getData(), DEGREE * sizeof(u64)) ||
        !reader.readBytes(ret[i].getB().getData(), DEGREE * sizeof(u64))) {
      throw std::runtime_error("Malformed query response from server");
    }
    ret[i].getA().setIsNTT(true);
    ret[i].getB().setIsNTT(true);
  }
  logToFile("Query round trip: " + std::to_string(duration_rt.count()) +
            "ms");

  std::vector<Message> dmsg;
  dmsg.reserve(iter);
  for (u64 j = 0; j < iter; ++j)
    dmsg.emplace_back(DEGREE);

  auto start_decrypt = std::chrono::high_resolution_clock::now();
  ctx->client->decryptScore(dmsg, ret, secKey_, ctx->outputScale);
  auto end_decrypt = std::chrono::high_resolution_clock::now();
  auto duration_decrypt = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_decrypt - start_decrypt);
  logToFile("Decrypt score: " + std::to_string(duration_decrypt.count()) +
            "ms");

  auto start_topk = std::chrono::high_resolution_clock::now();

  using Pair = std::pair<double, u64>;
  struct Compare {
    bool operator()(const Pair &a, const Pair &b) const noexcept {
      return a.first > b.first;
    }
  };
  std::priority_queue<Pair, std::vector<Pair>, Compare> min_heap;

  for (u64 i = 0; i < iter; ++i) {
    for (u64 j = 0; j < DEGREE; ++j) {
      u64 global_idx = i * DEGREE + j;
      if (global_idx >= db_size)
        break;

      double score = dmsg[i][j];

      if (min_heap.size() < k) {
        min_heap.push({score, global_idx});
      } else if (min_heap.top().first < score) {
        min_heap.pop();
        min_heap.push({score, global_idx});
      }
    }
  }

  res.clear();
  res.reserve(k);
  std::vector<std::pair<u64, float>> temp_results;
  temp_results.reserve(min_heap.size());

  while (!min_heap.empty()) {
    temp_results.push_back(
        {min_heap.top().second, static_cast<float>(min_heap.top().first)});
    min_heap.pop();
  }

  std::reverse(temp_results.begin(), temp_results.end());
  res = std::move(temp_results);

  auto end_topk = std::chrono::high_resolution_clock::now();
  auto duration_topk = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_topk - start_topk);
  logToFile("Top-K calculation: " + std::to_string(duration_topk.count()) +
            "ms");

  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);
  logToFile("Total queryAndTopKWithScores time: " +
            std::to_string(whole_duration.count()) + "ms");
}


std::vector<u64> HEVECClient::getTopKIndices(const std::vector<float> &scores,
                                           u64 k) {
  if (k == 0 || scores.empty()) {
    return {};
  }

  // Ensure k doesn't exceed the number of scores
  k = std::min(k, static_cast<u64>(scores.size()));

  // Use a min-heap to efficiently find top-k elements
  using Pair = std::pair<float, u64>;
  struct Compare {
    bool operator()(const Pair &a, const Pair &b) const noexcept {
      return a.first > b.first; // Min-heap: smallest score at top
    }
  };
  std::priority_queue<Pair, std::vector<Pair>, Compare> min_heap;

  // Process all scores
  for (u64 i = 0; i < scores.size(); ++i) {
    float score = scores[i];

    if (min_heap.size() < k) {
      min_heap.push({score, i});
    } else if (min_heap.top().first < score) {
      min_heap.pop();
      min_heap.push({score, i});
    }
  }

  // Extract results in descending order of scores
  std::vector<u64> result;
  result.reserve(k);
  std::vector<u64> temp;
  temp.reserve(min_heap.size());

  while (!min_heap.empty()) {
    temp.push_back(min_heap.top().second);
    min_heap.pop();
  }

  // Reverse to get highest scores first
  std::reverse(temp.begin(), temp.end());

  return temp;
}

std::string HEVECClient::retrieve(const std::string &collectionName, u64 index) {
  if (!collections_.count(collectionName)) {
    throw std::invalid_argument("Collection " + collectionName +
                                " does not exist.");
  }

  u64 collectionHash = std::hash<std::string>{}(collectionName);

  std::vector<uint8_t> body;
  appendBinary(body, collectionHash);
  u64 num_indices = 1;
  appendBinary(body, num_indices);
  appendBinary(body, index);

  auto response = performPost("/collections/retrieve", std::move(body));

  if (response.body().size() != PIR_PAYLOAD_SIZE) {
    throw std::runtime_error("Malformed retrieve response from server");
  }

  std::string aes_payload(PIR_PAYLOAD_SIZE, '\0');
  std::memcpy(aes_payload.data(), response.body().data(), PIR_PAYLOAD_SIZE);

  std::string decrypted_payload;
  decryptPayload(aes_payload, decrypted_payload, aesKey_, index);

  return decrypted_payload;
}


std::string HEVECClient::retrievePIR(const std::string &collectionName,
                                   u64 index) {
  if (!collections_.count(collectionName)) {
    throw std::invalid_argument("Collection " + collectionName +
                                " does not exist.");
  }
  auto &ctx = collections_.at(collectionName);
  const u64 db_size = db_sizes_.at(collectionName);

  if (index >= db_size) {
    throw std::invalid_argument("Index " + std::to_string(index) +
                                " is out of range. DB size is " +
                                std::to_string(db_size));
  }

  const u64 pir_db_size = PIR_RANK * PIR_RANK;
  if (db_size > pir_db_size) {
    throw std::runtime_error("Database size exceeds PIR capacity. Max size: " +
                             std::to_string(pir_db_size));
  }

  u64 collectionHash = std::hash<std::string>{}(collectionName);

  const double first_scale = std::pow(2.0, PIR_FIRST_SCALE);
  const double second_scale = std::pow(2.0, PIR_SECOND_SCALE);

  Ciphertext firstDim, secondDim;
  u64 row = index / PIR_RANK;
  u64 col = index % PIR_RANK;

  ctx->pirClient->encryptPIR(firstDim, row, secKey_, first_scale);
  ctx->pirClient->encryptPIR(secondDim, col, secKey_, second_scale);

  std::vector<uint8_t> body;
  appendBinary(body, collectionHash);
  appendBinary(body, firstDim.getA().getData(), DEGREE * sizeof(u64));
  appendBinary(body, firstDim.getB().getData(), DEGREE * sizeof(u64));
  appendBinary(body, secondDim.getA().getData(), DEGREE * sizeof(u64));
  appendBinary(body, secondDim.getB().getData(), DEGREE * sizeof(u64));

  auto response = performPost("/collections/pir_retrieve", std::move(body));

  if (response.body().size() != 2 * DEGREE * sizeof(u64)) {
    throw std::runtime_error("Malformed PIR retrieve response from server");
  }

  BinaryReader reader(response.body());
  Ciphertext result;
  reader.readBytes(result.getA().getData(), DEGREE * sizeof(u64));
  reader.readBytes(result.getB().getData(), DEGREE * sizeof(u64));
  result.getA().setIsNTT(true);
  result.getB().setIsNTT(true);

  Message dmsg(DEGREE);
  const double doubleScale = std::pow(2.0, PIR_FIRST_SCALE + PIR_SECOND_SCALE);
  ctx->pirClient->decrypt(dmsg, result, secKey_, doubleScale);

  unsigned char aes_payload[PIR_PAYLOAD_SIZE];
  ctx->pirClient->decodePIRPayload(aes_payload, dmsg);

  std::string decrypted_payload;
  decryptPayload(
      std::string(reinterpret_cast<char *>(aes_payload), PIR_PAYLOAD_SIZE),
      decrypted_payload, aesKey_, index);

  return decrypted_payload;
}


} // namespace HEVEC
