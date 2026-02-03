#include "HEVEC/HEVECClientTCP.hpp"

#include <asio/write.hpp>
#include <chrono>
#include <cmath>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include "HEVEC/HEVECOperation.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/Message.hpp"
#include "HEVEC/MetricType.hpp"
#include "HEVEC/TopK.hpp"

namespace HEVEC {

namespace {

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

} // namespace

struct HEVECClientTCP::CollectionContext {
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

HEVECClientTCP::HEVECClientTCP(const std::string &host, const std::string &port)
    : socket_(io_context_) {
  asio::ip::tcp::resolver resolver(io_context_);
  auto endpoints = resolver.resolve(host, port);
  asio::connect(socket_, endpoints);

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

HEVECClientTCP::~HEVECClientTCP() {
  try {
    terminate();
  } catch (const std::exception &e) {
    std::cerr << "Error during client termination: " << e.what() << std::endl;
  }
}

u64 HEVECClientTCP::setupCollection(const std::string &collectionName, u64 dimension,
                               const std::string &metric_type_str,
                               bool is_query_encrypt) {
  if (dimension == 0 || dimension > DEGREE) {
    throw std::invalid_argument("Dimension must be between 1 and " +
                                std::to_string(DEGREE));
  }

  Operation op = Operation::SETUP;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  // Send dimension and metric_type to server
  MetricType metric_type = stringToMetricType(metric_type_str);
  asio::write(socket_, asio::buffer(&dimension, sizeof(dimension)));
  asio::write(socket_, asio::buffer(&metric_type, sizeof(metric_type)));

  u8 setup_status;
  asio::read(socket_, asio::buffer(&setup_status, sizeof(setup_status)));

  if (setup_status == 2) { // Dimension mismatch
    throw std::runtime_error("Failed to setup collection '" + collectionName +
                             "': Dimension mismatch with server.");
  }

  if (setup_status == 0) { // Collection exists
    u64 server_dimension;
    MetricType server_metric_type;
    u64 server_db_size;

    asio::read(socket_,
               asio::buffer(&server_dimension, sizeof(server_dimension)));
    asio::read(socket_,
               asio::buffer(&server_metric_type, sizeof(server_metric_type)));
    asio::read(socket_, asio::buffer(&server_db_size, sizeof(server_db_size)));

    if (!collections_.count(collectionName)) {
      collections_[collectionName] = std::make_unique<CollectionContext>(
          server_dimension, server_metric_type, is_query_encrypt);
    }
    db_sizes_[collectionName] = server_db_size;
    logToFile("Collection '" + collectionName +
                "' already exists on server with size " +
                std::to_string(server_db_size) + ". Setup complete.");

    return server_db_size;
  }

  // setup_status == 1 (New collection)
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

  // Generate PIR-specific keys
  ctx->pirClient->genInvAutKeys(ctx->pirInvAutKeys.getKeys(), secKey_,
                                PIR_RANK);

  logToFile("Collection '" + collectionName + "' is new. Sending keys...");

  asio::write(socket_, asio::buffer(ctx->relinKey.getPolyAModQ().getData(),
                                    DEGREE * sizeof(u64)));
  asio::write(socket_, asio::buffer(ctx->relinKey.getPolyAModP().getData(),
                                    DEGREE * sizeof(u64)));
  asio::write(socket_, asio::buffer(ctx->relinKey.getPolyBModQ().getData(),
                                    DEGREE * sizeof(u64)));
  asio::write(socket_, asio::buffer(ctx->relinKey.getPolyBModP().getData(),
                                    DEGREE * sizeof(u64)));

  for (u64 i = 0; i < ctx->rank; ++i) {
    for (u64 j = 0; j < ctx->stack; ++j) {
      asio::write(
          socket_,
          asio::buffer(
              ctx->autedModPackKeys.getKeys()[i][j].getPolyAModQ().getData(),
              DEGREE * sizeof(u64)));
      asio::write(
          socket_,
          asio::buffer(
              ctx->autedModPackKeys.getKeys()[i][j].getPolyAModP().getData(),
              DEGREE * sizeof(u64)));
      asio::write(
          socket_,
          asio::buffer(
              ctx->autedModPackKeys.getKeys()[i][j].getPolyBModQ().getData(),
              DEGREE * sizeof(u64)));
      asio::write(
          socket_,
          asio::buffer(
              ctx->autedModPackKeys.getKeys()[i][j].getPolyBModP().getData(),
              DEGREE * sizeof(u64)));
    }
  }

  for (u64 i = 0; i < ctx->rank; ++i) {
    for (u64 j = 0; j < ctx->stack; ++j) {
      for (u64 k = 0; k < ctx->stack; ++k) {
        asio::write(socket_,
                    asio::buffer(ctx->autedModPackMLWEKeys.getKeys()[i][j]
                                     .getPolyAModQ(k)
                                     .getData(),
                                 ctx->rank * sizeof(u64)));
        asio::write(socket_,
                    asio::buffer(ctx->autedModPackMLWEKeys.getKeys()[i][j]
                                     .getPolyAModP(k)
                                     .getData(),
                                 ctx->rank * sizeof(u64)));
        asio::write(socket_,
                    asio::buffer(ctx->autedModPackMLWEKeys.getKeys()[i][j]
                                     .getPolyBModQ(k)
                                     .getData(),
                                 ctx->rank * sizeof(u64)));
        asio::write(socket_,
                    asio::buffer(ctx->autedModPackMLWEKeys.getKeys()[i][j]
                                     .getPolyBModP(k)
                                     .getData(),
                                 ctx->rank * sizeof(u64)));
      }
    }
  }

  // Send PIR InvAutKeys
  for (u64 i = 0; i < PIR_RANK; ++i) {
    asio::write(
        socket_,
        asio::buffer(ctx->pirInvAutKeys.getKeys()[i].getPolyAModQ().getData(),
                     DEGREE * sizeof(u64)));
    asio::write(
        socket_,
        asio::buffer(ctx->pirInvAutKeys.getKeys()[i].getPolyAModP().getData(),
                     DEGREE * sizeof(u64)));
    asio::write(
        socket_,
        asio::buffer(ctx->pirInvAutKeys.getKeys()[i].getPolyBModQ().getData(),
                     DEGREE * sizeof(u64)));
    asio::write(
        socket_,
        asio::buffer(ctx->pirInvAutKeys.getKeys()[i].getPolyBModP().getData(),
                     DEGREE * sizeof(u64)));
  }

  return 0; // New collection starts with size 0
}

void HEVECClientTCP::terminate() {
  Operation op = Operation::TERMINATE;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));
}

void HEVECClientTCP::dropCollection(const std::string &collectionName) {
  Operation op = Operation::DROP_COLLECTION;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  // Remove from client-side collections
  collections_.erase(collectionName);
  db_sizes_.erase(collectionName);

  logToFile("Dropped collection '" + collectionName + "'");
}

void HEVECClientTCP::insert(const std::string &collectionName,
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

  Operation op = Operation::INSERT;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  u64 num_to_insert = db.size();
  asio::write(socket_, asio::buffer(&num_to_insert, sizeof(num_to_insert)));

  u64 current_db_size = db_sizes_.at(collectionName);
  std::string aes_payload(PIR_PAYLOAD_SIZE, '\0');
  for (size_t i = 0; i < db.size(); ++i) {
    const auto &vec = db[i];
    Message msg(ctx->rank);
    for (u64 k = 0; k < vec.size(); ++k)
      msg[k] = vec[k];

    MLWECiphertext key_to_send(ctx->rank);
    ctx->client->encryptKey(key_to_send, msg, secKey_, ctx->keyScale);

    for (u64 k = 0; k < ctx->stack; ++k)
      asio::write(socket_, asio::buffer(key_to_send.getA(k).getData(),
                                        ctx->rank * sizeof(u64)));
    asio::write(socket_, asio::buffer(key_to_send.getB().getData(),
                                      ctx->rank * sizeof(u64)));

    // Encrypt and Send payload
    u64 global_idx = current_db_size + i;
    encryptPayload(payloads[i], aes_payload, aesKey_, global_idx);
    asio::write(socket_, asio::buffer(aes_payload.data(), PIR_PAYLOAD_SIZE));
  }

  db_sizes_.at(collectionName) += num_to_insert;
  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);
  logToFile("Sent " + std::to_string(num_to_insert) +
              " keys to server. Total time: " +
              std::to_string(whole_duration.count()) + "ms");
}

std::vector<float> HEVECClientTCP::query(const std::string &collectionName,
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

  Operation op = ctx->isQueryEncrypt ? Operation::QUERY : Operation::QUERY_PTXT;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  const u64 iter = (db_sizes_.at(collectionName) + DEGREE - 1) / DEGREE;

  Message msg(ctx->rank);
  for (u64 j = 0; j < query_vec.size(); ++j)
    msg[j] = query_vec[j];

  auto start = std::chrono::high_resolution_clock::now();

  if (ctx->isQueryEncrypt) {
    MLWECiphertext query(ctx->rank);
    ctx->client->encryptQuery(query, msg, secKey_, ctx->queryScale);

    for (u64 i = 0; i < ctx->stack; ++i)
      asio::write(socket_, asio::buffer(query.getA(i).getData(),
                                        ctx->rank * sizeof(u64)));
    asio::write(socket_,
                asio::buffer(query.getB().getData(), ctx->rank * sizeof(u64)));
  } else {
    Polynomial query(ctx->rank, MOD_Q);
    ctx->client->encodeQuery(query, msg, ctx->queryScale);

    asio::write(socket_,
                asio::buffer(query.getData(), ctx->rank * sizeof(u64)));
  }

  auto end = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  logToFile("Encrypt/Encode query: " + std::to_string(duration.count()) +
              "ms");

  start = std::chrono::high_resolution_clock::now();
  std::vector<Ciphertext> ret(iter);
  std::vector<Message> dmsg;
  dmsg.reserve(iter);
  for (u64 j = 0; j < iter; ++j)
    dmsg.emplace_back(DEGREE);

  for (u64 i = 0; i < iter; ++i) {
    asio::read(socket_,
               asio::buffer(ret[i].getA().getData(), DEGREE * sizeof(u64)));
    ret[i].getA().setIsNTT(true);
    asio::read(socket_,
               asio::buffer(ret[i].getB().getData(), DEGREE * sizeof(u64)));
    ret[i].getB().setIsNTT(true);
  }
  end = std::chrono::high_resolution_clock::now();
  duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  logToFile("Query round trip: " + std::to_string(duration.count()) + "ms");

  start = std::chrono::high_resolution_clock::now();
  ctx->client->decryptScore(dmsg, ret, secKey_, ctx->outputScale);
  end = std::chrono::high_resolution_clock::now();
  duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  logToFile("Decrypt score: " + std::to_string(duration.count()) + "ms");

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

void HEVECClientTCP::queryAndTopK(TopK &res, const std::string &collectionName,
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

  // --- Network and crypto part, same as in query() ---
  Operation op = ctx->isQueryEncrypt ? Operation::QUERY : Operation::QUERY_PTXT;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  const u64 iter = (db_size + DEGREE - 1) / DEGREE;

  Message msg(ctx->rank);
  for (u64 j = 0; j < query_vec.size(); ++j)
    msg[j] = query_vec[j];

  auto start_enc = std::chrono::high_resolution_clock::now();

  if (ctx->isQueryEncrypt) {
    // Encrypted query logic
    MLWECiphertext query(ctx->rank);
    ctx->client->encryptQuery(query, msg, secKey_, ctx->queryScale);

    for (u64 i = 0; i < ctx->stack; ++i)
      asio::write(socket_, asio::buffer(query.getA(i).getData(),
                                        ctx->rank * sizeof(u64)));
    asio::write(socket_,
                asio::buffer(query.getB().getData(), ctx->rank * sizeof(u64)));
  } else {
    // Plaintext query logic
    Polynomial query(ctx->rank, MOD_Q);
    ctx->client->encodeQuery(query, msg, ctx->queryScale);

    asio::write(socket_,
                asio::buffer(query.getData(), ctx->rank * sizeof(u64)));
  }

  auto end_enc = std::chrono::high_resolution_clock::now();
  auto duration_enc = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_enc - start_enc);
  logToFile("Encrypt/Encode query: " + std::to_string(duration_enc.count()) +
              "ms");

  auto start_rt = std::chrono::high_resolution_clock::now();
  std::vector<Ciphertext> ret(iter);
  for (u64 i = 0; i < iter; ++i) {
    asio::read(socket_,
               asio::buffer(ret[i].getA().getData(), DEGREE * sizeof(u64)));
    ret[i].getA().setIsNTT(true);
    asio::read(socket_,
               asio::buffer(ret[i].getB().getData(), DEGREE * sizeof(u64)));
    ret[i].getB().setIsNTT(true);
  }
  auto end_rt = std::chrono::high_resolution_clock::now();
  auto duration_rt =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_rt - start_rt);
  logToFile("Query round trip: " + std::to_string(duration_rt.count()) +
              "ms");

  // --- Decrypt all scores ---
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

  // --- Efficient Top-K using a min-heap ---
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

void HEVECClientTCP::queryAndTopKWithScores(std::vector<std::pair<u64, float>> &res,
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

  // --- Network and crypto part, same as in query() ---
  Operation op = ctx->isQueryEncrypt ? Operation::QUERY : Operation::QUERY_PTXT;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  const u64 iter = (db_size + DEGREE - 1) / DEGREE;

  Message msg(ctx->rank);
  for (u64 j = 0; j < query_vec.size(); ++j)
    msg[j] = query_vec[j];

  auto start_enc = std::chrono::high_resolution_clock::now();

  if (ctx->isQueryEncrypt) {
    // Encrypted query logic
    MLWECiphertext query(ctx->rank);
    ctx->client->encryptQuery(query, msg, secKey_, ctx->queryScale);

    for (u64 i = 0; i < ctx->stack; ++i)
      asio::write(socket_, asio::buffer(query.getA(i).getData(),
                                        ctx->rank * sizeof(u64)));
    asio::write(socket_,
                asio::buffer(query.getB().getData(), ctx->rank * sizeof(u64)));
  } else {
    // Plaintext query logic
    Polynomial query(ctx->rank, MOD_Q);
    ctx->client->encodeQuery(query, msg, ctx->queryScale);

    asio::write(socket_,
                asio::buffer(query.getData(), ctx->rank * sizeof(u64)));
  }

  auto end_enc = std::chrono::high_resolution_clock::now();
  auto duration_enc = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_enc - start_enc);
  logToFile("Encrypt/Encode query: " + std::to_string(duration_enc.count()) +
              "ms");

  auto start_rt = std::chrono::high_resolution_clock::now();
  std::vector<Ciphertext> ret(iter);
  for (u64 i = 0; i < iter; ++i) {
    asio::read(socket_,
               asio::buffer(ret[i].getA().getData(), DEGREE * sizeof(u64)));
    ret[i].getA().setIsNTT(true);
    asio::read(socket_,
               asio::buffer(ret[i].getB().getData(), DEGREE * sizeof(u64)));
    ret[i].getB().setIsNTT(true);
  }
  auto end_rt = std::chrono::high_resolution_clock::now();
  auto duration_rt =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_rt - start_rt);
  logToFile("Query round trip: " + std::to_string(duration_rt.count()) +
              "ms");

  // --- Decrypt all scores ---
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

  // --- Efficient Top-K using a min-heap ---
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

  // Convert to result format: (index, score) pairs
  res.clear();
  res.reserve(k);
  std::vector<std::pair<u64, float>> temp_results;
  temp_results.reserve(min_heap.size());

  while (!min_heap.empty()) {
    temp_results.push_back(
        {min_heap.top().second, static_cast<float>(min_heap.top().first)});
    min_heap.pop();
  }

  // Reverse to get highest scores first
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

std::vector<u64> HEVECClientTCP::getTopKIndices(const std::vector<float> &scores,
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

std::string HEVECClientTCP::retrieve(const std::string &collectionName, u64 index) {
  if (!collections_.count(collectionName)) {
    throw std::invalid_argument("Collection " + collectionName +
                                " does not exist.");
  }

  Operation op = Operation::RETRIEVE;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  u64 num_indices = 1;
  asio::write(socket_, asio::buffer(&num_indices, sizeof(num_indices)));
  asio::write(socket_, asio::buffer(&index, sizeof(index)));

  std::string aes_payload(PIR_PAYLOAD_SIZE, '\0');
  std::string decrypted_payload;

  asio::read(socket_, asio::buffer(&aes_payload[0], PIR_PAYLOAD_SIZE));
  decryptPayload(aes_payload, decrypted_payload, aesKey_, index);

  return decrypted_payload;
}

std::string HEVECClientTCP::retrievePIR(const std::string &collectionName,
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

  // Check PIR capacity
  const u64 pir_db_size = PIR_RANK * PIR_RANK;
  if (db_size > pir_db_size) {
    throw std::runtime_error("Database size exceeds PIR capacity. Max size: " +
                             std::to_string(pir_db_size));
  }

  Operation op = Operation::PIR_RETRIEVE;
  asio::write(socket_, asio::buffer(&op, sizeof(op)));

  u64 collectionHash = std::hash<std::string>{}(collectionName);
  asio::write(socket_, asio::buffer(&collectionHash, sizeof(collectionHash)));

  // Send encrypted PIR queries using PIR-specific scale
  const double scale = std::pow(2.0, PIR_FIRST_SCALE);
  Ciphertext firstDim, secondDim;

  // Compute 2D indices for PIR grid
  u64 row = index / PIR_RANK;
  u64 col = index % PIR_RANK;

  ctx->pirClient->encryptPIR(firstDim, row, secKey_, scale);
  ctx->pirClient->encryptPIR(secondDim, col, secKey_,
                             std::pow(2.0, PIR_SECOND_SCALE));

  // Send first dimension query
  asio::write(socket_,
              asio::buffer(firstDim.getA().getData(), DEGREE * sizeof(u64)));
  asio::write(socket_,
              asio::buffer(firstDim.getB().getData(), DEGREE * sizeof(u64)));

  // Send second dimension query
  asio::write(socket_,
              asio::buffer(secondDim.getA().getData(), DEGREE * sizeof(u64)));
  asio::write(socket_,
              asio::buffer(secondDim.getB().getData(), DEGREE * sizeof(u64)));

  // Receive encrypted result
  Ciphertext result;
  asio::read(socket_,
             asio::buffer(result.getA().getData(), DEGREE * sizeof(u64)));
  result.getA().setIsNTT(true);
  asio::read(socket_,
             asio::buffer(result.getB().getData(), DEGREE * sizeof(u64)));
  result.getB().setIsNTT(true);

  // Decrypt the result
  Message dmsg(DEGREE);
  const double doubleScale = std::pow(2.0, PIR_FIRST_SCALE + PIR_SECOND_SCALE);
  ctx->pirClient->decrypt(dmsg, result, secKey_, doubleScale);

  // Decode PIR payload from polynomial
  unsigned char aes_payload[PIR_PAYLOAD_SIZE];
  ctx->pirClient->decodePIRPayload(aes_payload, dmsg);

  // Decrypt AES payload
  std::string decrypted_payload;
  decryptPayload(
      std::string(reinterpret_cast<char *>(aes_payload), PIR_PAYLOAD_SIZE),
      decrypted_payload, aesKey_, index);

  return decrypted_payload;
}

} // namespace HEVEC
