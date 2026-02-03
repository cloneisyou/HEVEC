#include "HEVEC/HEVECServerTCP.hpp"

#include <asio/bind_executor.hpp>
#include <asio/error_code.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Client.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/HEVECOperation.hpp"
#include "HEVEC/Keys.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/MetricType.hpp"
#include "HEVEC/PIRServer.hpp"
#include "HEVEC/Server.hpp"
#include "HEVEC/SwitchingKey.hpp"

namespace HEVEC {

namespace {

void logToFile(const std::string &message) {
  const char *log_path_env = std::getenv("HEVEC_SERVER_LOG_PATH");
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

constexpr u64 LOG_RANK = 7;
constexpr u64 RANK = 1ULL << LOG_RANK;
constexpr u64 STACK = DEGREE / RANK;

// PIR-specific constants from ex5-pir.cpp
constexpr u64 PIR_LOG_RANK = 10;
constexpr u64 PIR_RANK = 1ULL << PIR_LOG_RANK;
} // namespace

struct HEVECServerTCP::CollectionData {
  std::mutex mtx;
  std::unique_ptr<Server> server;
  SwitchingKey relinKey;
  AutedModPackKeys autedModPackKeys;
  AutedModPackMLWEKeys autedModPackMLWEKeys;

  // PIR-specific
  InvAutKeys pirInvAutKeys;
  std::vector<Polynomial> pir_encoded_payloads_;

  std::vector<CachedKeys> full_block_caches_;
  std::vector<MLWECiphertext> partial_block_keys_;
  std::unique_ptr<CachedKeys> partial_block_cache_;
  std::vector<std::string> payloads_;

  u64 log_rank;
  u64 rank;
  u64 stack;
  u64 dimension;
  MetricType metric_type;
  u64 db_size = 0;

  CollectionData(u64 d, MetricType mt, SwitchingKey &&rk,
                 AutedModPackKeys &&apk, AutedModPackMLWEKeys &&apmk,
                 InvAutKeys &&piak)
      : relinKey(std::move(rk)), autedModPackKeys(std::move(apk)),
        autedModPackMLWEKeys(std::move(apmk)), pirInvAutKeys(std::move(piak)),
        dimension(d), metric_type(mt),
        pir_encoded_payloads_(PIR_RANK * PIR_RANK, Polynomial(DEGREE, MOD_Q)) {
    log_rank = static_cast<u64>(std::ceil(std::log2(dimension)));
    rank = 1ULL << log_rank;
    stack = DEGREE / rank;
    for (u64 i = 0; i < PIR_RANK * PIR_RANK; ++i) {
      pir_encoded_payloads_[i].setIsNTT(true);
    }
    partial_block_keys_.reserve(DEGREE);
    server = std::make_unique<Server>(log_rank, relinKey, autedModPackKeys,
                                      autedModPackMLWEKeys);
  }
};

class HEVECServerTCP::Session : public std::enable_shared_from_this<Session> {
  tcp::socket sock_;
  HEVECServerTCP &server_;
  asio::strand<asio::basic_socket<asio::ip::tcp>::executor_type> st;

  void handleSetup() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));

    // Read dimension and metric_type from client
    u64 dimension;
    asio::read(sock_, asio::buffer(&dimension, sizeof(dimension)));
    MetricType metric_type;
    asio::read(sock_, asio::buffer(&metric_type, sizeof(metric_type)));

    std::shared_ptr<CollectionData> ctx;
    {
      std::lock_guard<std::mutex> lock(server_.collections_mutex_);
      if (server_.collections_.count(collectionHash)) {
        ctx = server_.collections_.at(collectionHash);
      }
    }

    if (ctx) {
      std::lock_guard<std::mutex> lock(ctx->mtx);
      if (ctx->dimension != dimension) {
        u8 status = 2; // Error: Dimension mismatch
        asio::write(sock_, asio::buffer(&status, sizeof(status)));
        std::cerr << "Collection " << collectionHash
                  << " setup failed: Dimension mismatch. Got " << dimension
                  << ", expected " << ctx->dimension << std::endl;
        return;
      } else {
        u8 status = 0; // OK: Exists
        asio::write(sock_, asio::buffer(&status, sizeof(status)));
        // Send back stored info
        asio::write(sock_,
                    asio::buffer(&ctx->dimension, sizeof(ctx->dimension)));
        asio::write(sock_,
                    asio::buffer(&ctx->metric_type, sizeof(ctx->metric_type)));
        asio::write(sock_, asio::buffer(&ctx->db_size, sizeof(ctx->db_size)));

        logToFile("Collection " + std::to_string(collectionHash) +
                    " re-connected. DB size: " + std::to_string(ctx->db_size));
        return;
      }
    }

    u8 status = 1; // OK: New collection
    asio::write(sock_, asio::buffer(&status, sizeof(status)));

    u64 log_rank = static_cast<u64>(std::ceil(std::log2(dimension)));
    u64 rank = 1ULL << log_rank;
    u64 stack = DEGREE / rank;

    SwitchingKey relinKey;
    AutedModPackKeys autedModPackKeys(rank);
    AutedModPackMLWEKeys autedModPackMLWEKeys(rank);
    InvAutKeys pirInvAutKeys(PIR_RANK);

    // Reading all keys without lock
    asio::read(sock_, asio::buffer(relinKey.getPolyAModQ().getData(),
                                   DEGREE * sizeof(u64)));
    relinKey.getPolyAModQ().setIsNTT(true);
    asio::read(sock_, asio::buffer(relinKey.getPolyAModP().getData(),
                                   DEGREE * sizeof(u64)));
    relinKey.getPolyAModP().setIsNTT(true);
    asio::read(sock_, asio::buffer(relinKey.getPolyBModQ().getData(),
                                   DEGREE * sizeof(u64)));
    relinKey.getPolyBModQ().setIsNTT(true);
    asio::read(sock_, asio::buffer(relinKey.getPolyBModP().getData(),
                                   DEGREE * sizeof(u64)));
    relinKey.getPolyBModP().setIsNTT(true);
    for (u64 i = 0; i < rank; ++i) {
      for (u64 j = 0; j < stack; ++j) {
        asio::read(
            sock_,
            asio::buffer(
                autedModPackKeys.getKeys()[i][j].getPolyAModQ().getData(),
                DEGREE * sizeof(u64)));
        autedModPackKeys.getKeys()[i][j].getPolyAModQ().setIsNTT(true);
        asio::read(
            sock_,
            asio::buffer(
                autedModPackKeys.getKeys()[i][j].getPolyAModP().getData(),
                DEGREE * sizeof(u64)));
        autedModPackKeys.getKeys()[i][j].getPolyAModP().setIsNTT(true);
        asio::read(
            sock_,
            asio::buffer(
                autedModPackKeys.getKeys()[i][j].getPolyBModQ().getData(),
                DEGREE * sizeof(u64)));
        autedModPackKeys.getKeys()[i][j].getPolyBModQ().setIsNTT(true);
        asio::read(
            sock_,
            asio::buffer(
                autedModPackKeys.getKeys()[i][j].getPolyBModP().getData(),
                DEGREE * sizeof(u64)));
        autedModPackKeys.getKeys()[i][j].getPolyBModP().setIsNTT(true);
      }
    }
    for (u64 i = 0; i < rank; ++i) {
      for (u64 j = 0; j < stack; ++j) {
        for (u64 k = 0; k < stack; ++k) {
          asio::read(sock_, asio::buffer(autedModPackMLWEKeys.getKeys()[i][j]
                                             .getPolyAModQ(k)
                                             .getData(),
                                         rank * sizeof(u64)));
          autedModPackMLWEKeys.getKeys()[i][j].getPolyAModQ(k).setIsNTT(true);
          asio::read(sock_, asio::buffer(autedModPackMLWEKeys.getKeys()[i][j]
                                             .getPolyAModP(k)
                                             .getData(),
                                         rank * sizeof(u64)));
          autedModPackMLWEKeys.getKeys()[i][j].getPolyAModP(k).setIsNTT(true);
          asio::read(sock_, asio::buffer(autedModPackMLWEKeys.getKeys()[i][j]
                                             .getPolyBModQ(k)
                                             .getData(),
                                         rank * sizeof(u64)));
          autedModPackMLWEKeys.getKeys()[i][j].getPolyBModQ(k).setIsNTT(true);
          asio::read(sock_, asio::buffer(autedModPackMLWEKeys.getKeys()[i][j]
                                             .getPolyBModP(k)
                                             .getData(),
                                         rank * sizeof(u64)));
          autedModPackMLWEKeys.getKeys()[i][j].getPolyBModP(k).setIsNTT(true);
        }
      }
    }

    // Read PIR InvAutKeys
    for (u64 i = 0; i < PIR_RANK; ++i) {
      asio::read(sock_, asio::buffer(
                            pirInvAutKeys.getKeys()[i].getPolyAModQ().getData(),
                            DEGREE * sizeof(u64)));
      pirInvAutKeys.getKeys()[i].getPolyAModQ().setIsNTT(true);
      asio::read(sock_, asio::buffer(
                            pirInvAutKeys.getKeys()[i].getPolyAModP().getData(),
                            DEGREE * sizeof(u64)));
      pirInvAutKeys.getKeys()[i].getPolyAModP().setIsNTT(true);
      asio::read(sock_, asio::buffer(
                            pirInvAutKeys.getKeys()[i].getPolyBModQ().getData(),
                            DEGREE * sizeof(u64)));
      pirInvAutKeys.getKeys()[i].getPolyBModQ().setIsNTT(true);
      asio::read(sock_, asio::buffer(
                            pirInvAutKeys.getKeys()[i].getPolyBModP().getData(),
                            DEGREE * sizeof(u64)));
      pirInvAutKeys.getKeys()[i].getPolyBModP().setIsNTT(true);
    }

    auto new_collection = std::make_shared<CollectionData>(
        dimension, metric_type, std::move(relinKey),
        std::move(autedModPackKeys), std::move(autedModPackMLWEKeys),
        std::move(pirInvAutKeys));

    {
      std::lock_guard<std::mutex> lock(server_.collections_mutex_);
      server_.collections_[collectionHash] = new_collection;
    }

    logToFile("Collection " + std::to_string(collectionHash) +
                " with dimension " + std::to_string(dimension) + " set up.");
  }

  std::shared_ptr<CollectionData> getCollection(u64 collectionHash) {
    std::lock_guard<std::mutex> lock(server_.collections_mutex_);
    if (!server_.collections_.count(collectionHash)) {
      throw std::runtime_error("Collection not found: " +
                               std::to_string(collectionHash));
    }
    return server_.collections_.at(collectionHash);
  }

  void handleInsert() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));
    auto ctx = getCollection(collectionHash);
    std::lock_guard<std::mutex> lock(ctx->mtx);

    u64 num_to_insert;
    asio::read(sock_, asio::buffer(&num_to_insert, sizeof(num_to_insert)));
    auto whole_start = std::chrono::high_resolution_clock::now();

    // Create PIR encoder client if needed
    Client pirClient(PIR_LOG_RANK);

    for (u64 i = 0; i < num_to_insert; ++i) {
      MLWECiphertext new_key(ctx->rank);
      for (u64 k = 0; k < ctx->stack; ++k) {
        asio::read(sock_, asio::buffer(new_key.getA(k).getData(),
                                       ctx->rank * sizeof(u64)));
      }
      asio::read(sock_, asio::buffer(new_key.getB().getData(),
                                     ctx->rank * sizeof(u64)));

      std::string payload(1024, '\0');
      asio::read(sock_, asio::buffer(&payload[0], 1024));
      ctx->payloads_.push_back(payload);

      // Encode payload for PIR
      const unsigned char *payload_data =
          reinterpret_cast<const unsigned char *>(payload.data());
      pirClient.encodePIRPayload(ctx->pir_encoded_payloads_[ctx->db_size + i],
                                 payload_data);

      ctx->partial_block_keys_.push_back(std::move(new_key));

      if (ctx->partial_block_keys_.size() == DEGREE) {
        ctx->full_block_caches_.emplace_back(ctx->rank);
        auto start = std::chrono::high_resolution_clock::now();
        ctx->server->cacheKeys(ctx->full_block_caches_.back(),
                               ctx->partial_block_keys_);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        logToFile("Cache full block: " + std::to_string(duration.count()) +
                    "ms");
        ctx->partial_block_keys_.clear();
        ctx->partial_block_cache_.reset();
      }
    }

    if (!ctx->partial_block_keys_.empty()) {
      ctx->partial_block_cache_ = std::make_unique<CachedKeys>(ctx->rank);
      std::vector<MLWECiphertext> padded_block = ctx->partial_block_keys_;
      padded_block.resize(DEGREE, MLWECiphertext(ctx->rank));
      auto start = std::chrono::high_resolution_clock::now();
      ctx->server->cacheKeys(*ctx->partial_block_cache_, padded_block);
      auto end = std::chrono::high_resolution_clock::now();
      auto duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      logToFile("Cache partial block: " + std::to_string(duration.count()) +
                  "ms");
    }

    auto whole_end = std::chrono::high_resolution_clock::now();
    auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        whole_end - whole_start);
    ctx->db_size += num_to_insert;
    logToFile("Inserted " + std::to_string(num_to_insert) +
                " items into collection " + std::to_string(collectionHash) +
                ". Total DB size: " + std::to_string(ctx->db_size) +
                ". Took: " + std::to_string(whole_duration.count()) + "ms");
  }

  void handleQuery() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));
    auto ctx = getCollection(collectionHash);
    std::lock_guard<std::mutex> lock(ctx->mtx);

    auto whole_start = std::chrono::high_resolution_clock::now();
    MLWECiphertext query(ctx->rank);
    CachedQuery queryCache(ctx->rank);

    for (u64 i = 0; i < ctx->stack; ++i)
      asio::read(sock_, asio::buffer(query.getA(i).getData(),
                                     ctx->rank * sizeof(u64)));
    asio::read(sock_,
               asio::buffer(query.getB().getData(), ctx->rank * sizeof(u64)));

    auto start = std::chrono::high_resolution_clock::now();
    ctx->server->cacheQuery(queryCache, query);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    logToFile("Cache query: " + std::to_string(duration.count()) + "ms");

    const u64 iter = ctx->full_block_caches_.size();
    auto total_inner_product_duration = std::chrono::milliseconds(0);

    for (u64 i = 0; i < iter; ++i) {
      Ciphertext res;
      start = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(res, queryCache, ctx->full_block_caches_[i]);
      end = std::chrono::high_resolution_clock::now();
      duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      total_inner_product_duration += duration;

      asio::async_write(
          sock_, asio::buffer(res.getA().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
      asio::async_write(
          sock_, asio::buffer(res.getB().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
    }

    logToFile("Inner product for full blocks: " +
                std::to_string(total_inner_product_duration.count()) + "ms");

    if (ctx->partial_block_cache_) {
      Ciphertext partial_res;
      start = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(partial_res, queryCache,
                                *ctx->partial_block_cache_);
      end = std::chrono::high_resolution_clock::now();
      duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      logToFile("Inner product for partial block: " +
                  std::to_string(duration.count()) + "ms");

      asio::async_write(
          sock_,
          asio::buffer(partial_res.getA().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
      asio::async_write(
          sock_,
          asio::buffer(partial_res.getB().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
    }
    auto whole_end = std::chrono::high_resolution_clock::now();
    auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        whole_end - whole_start);
    logToFile("Total query handling time: " +
                std::to_string(whole_duration.count()) + "ms");
  }

  void handleQueryPtxt() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));
    auto ctx = getCollection(collectionHash);
    std::lock_guard<std::mutex> lock(ctx->mtx);

    auto whole_start = std::chrono::high_resolution_clock::now();
    Polynomial query(ctx->rank, MOD_Q);
    CachedPlaintextQuery queryCache(ctx->rank);

    asio::read(sock_, asio::buffer(query.getData(), ctx->rank * sizeof(u64)));
    query.setIsNTT(true);

    auto start = std::chrono::high_resolution_clock::now();
    ctx->server->cacheQuery(queryCache, query);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    logToFile("Cache plaintext query: " + std::to_string(duration.count()) +
                "ms");

    const u64 iter = ctx->full_block_caches_.size();
    auto total_inner_product_duration = std::chrono::milliseconds(0);

    for (u64 i = 0; i < iter; ++i) {
      Ciphertext res;
      start = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(res, queryCache, ctx->full_block_caches_[i]);
      end = std::chrono::high_resolution_clock::now();
      duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      total_inner_product_duration += duration;

      asio::async_write(
          sock_, asio::buffer(res.getA().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
      asio::async_write(
          sock_, asio::buffer(res.getB().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
    }

    logToFile("Inner product for full blocks (plaintext): " +
                std::to_string(total_inner_product_duration.count()) + "ms");

    if (ctx->partial_block_cache_) {
      Ciphertext partial_res;
      start = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(partial_res, queryCache,
                                *ctx->partial_block_cache_);
      end = std::chrono::high_resolution_clock::now();
      duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      logToFile("Inner product for partial block (plaintext): " +
                  std::to_string(duration.count()) + "ms");

      asio::async_write(
          sock_,
          asio::buffer(partial_res.getA().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
      asio::async_write(
          sock_,
          asio::buffer(partial_res.getB().getData(), DEGREE * sizeof(u64)),
          asio::bind_executor(st, [](auto, size_t) {}));
    }

    auto whole_end = std::chrono::high_resolution_clock::now();
    auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        whole_end - whole_start);
    logToFile("Total plaintext query handling time: " +
                std::to_string(whole_duration.count()) + "ms");
  }

  void handleRetrieve() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));
    auto ctx = getCollection(collectionHash);
    std::lock_guard<std::mutex> lock(ctx->mtx);

    u64 num_indices;
    asio::read(sock_, asio::buffer(&num_indices, sizeof(num_indices)));

    std::string empty_payload(1024, '\0');
    for (u64 i = 0; i < num_indices; ++i) {
      u64 index;
      asio::read(sock_, asio::buffer(&index, sizeof(index)));
      if (index < ctx->db_size) {
        asio::write(sock_, asio::buffer(ctx->payloads_[index].data(), 1024));
      } else {
        asio::write(sock_, asio::buffer(empty_payload.data(), 1024));
      }
    }
  }

  void handlePirRetrieve() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));
    auto ctx = getCollection(collectionHash);
    std::lock_guard<std::mutex> lock(ctx->mtx);

    if (ctx->db_size == 0) {
      throw std::runtime_error("Database is empty");
    }

    const u64 pir_db_size = PIR_RANK * PIR_RANK;
    if (ctx->db_size > pir_db_size) {
      throw std::runtime_error("Database size exceeds PIR capacity");
    }

    // Receive encrypted PIR queries
    Ciphertext firstDim, secondDim;

    asio::read(sock_,
               asio::buffer(firstDim.getA().getData(), DEGREE * sizeof(u64)));
    asio::read(sock_,
               asio::buffer(firstDim.getB().getData(), DEGREE * sizeof(u64)));

    asio::read(sock_,
               asio::buffer(secondDim.getA().getData(), DEGREE * sizeof(u64)));
    asio::read(sock_,
               asio::buffer(secondDim.getB().getData(), DEGREE * sizeof(u64)));
    // Perform PIR computation with shared relinKey and PIR-specific invAutKeys
    PIRServer pirServer(PIR_LOG_RANK, ctx->relinKey, ctx->pirInvAutKeys);
    Ciphertext result;
    pirServer.pir(result, firstDim, secondDim, ctx->pir_encoded_payloads_);

    // Send back encrypted result
    asio::write(sock_,
                asio::buffer(result.getA().getData(), DEGREE * sizeof(u64)));
    asio::write(sock_,
                asio::buffer(result.getB().getData(), DEGREE * sizeof(u64)));
  }

  void handleDropCollection() {
    u64 collectionHash;
    asio::read(sock_, asio::buffer(&collectionHash, sizeof(collectionHash)));

    {
      std::lock_guard<std::mutex> lock(server_.collections_mutex_);
      auto it = server_.collections_.find(collectionHash);
      if (it != server_.collections_.end()) {
        server_.collections_.erase(it);
        logToFile("Collection " + std::to_string(collectionHash) +
                    " dropped successfully.");
      } else {
        logToFile("Failed to drop collection " +
                    std::to_string(collectionHash) + ": not found.");
      }
    }
  }

public:
  explicit Session(tcp::socket s, HEVECServerTCP &server)
      : sock_(std::move(s)), server_(server), st(sock_.get_executor()) {}

  void start() {
    while (true) {
      try {
        Operation op;
        asio::read(sock_, asio::buffer(&op, sizeof(op)));

        if (op == Operation::SETUP) {
          handleSetup();
        } else if (op == Operation::INSERT) {
          handleInsert();
        } else if (op == Operation::QUERY) {
          handleQuery();
        } else if (op == Operation::QUERY_PTXT) {
          handleQueryPtxt();
        } else if (op == Operation::RETRIEVE) {
          handleRetrieve();
        } else if (op == Operation::PIR_RETRIEVE) {
          handlePirRetrieve();
        } else if (op == Operation::DROP_COLLECTION) {
          handleDropCollection();
        } else if (op == Operation::TERMINATE) {
          logToFile("Terminate signal received. Closing session.");
          break;
        } else {
          std::cerr << "Unknown operation received. Closing session."
                    << std::endl;
          break;
        }
      } catch (const std::exception &e) {
        std::cerr << "Exception in session: " << e.what()
                  << ". Closing session." << std::endl;
        break;
      }
    }
  }
};

HEVECServerTCP::HEVECServerTCP(unsigned short port)
    : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {
  doAccept();
}

void HEVECServerTCP::run() { io_context_.run(); }

void HEVECServerTCP::doAccept() {
  acceptor_.async_accept([this](asio::error_code ec, tcp::socket socket) {
    if (!ec) {
      std::make_shared<Session>(std::move(socket), *this)->start();
    }
    doAccept();
  });
}

} // namespace HEVEC
