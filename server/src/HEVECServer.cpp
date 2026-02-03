#include "HEVEC/HEVECServer.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Client.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/Keys.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/MetricType.hpp"
#include "HEVEC/PIRServer.hpp"
#include "HEVEC/Server.hpp"
#include "HEVEC/SwitchingKey.hpp"

namespace HEVEC {
namespace {

using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;

using Body = http::vector_body<uint8_t>;
using Request = http::request<Body>;
using Response = http::response<Body>;

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

  std::size_t remaining() const { return buffer.size() - pos; }
};

template <typename T>
void appendBinary(std::vector<uint8_t> &out, const T &value) {
  const auto *ptr = reinterpret_cast<const uint8_t *>(&value);
  out.insert(out.end(), ptr, ptr + sizeof(T));
}

void appendBinary(std::vector<uint8_t> &out, const void *data,
                  std::size_t len) {
  const auto *ptr = static_cast<const uint8_t *>(data);
  out.insert(out.end(), ptr, ptr + len);
}

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

constexpr u64 PIR_LOG_RANK = 10;
constexpr u64 PIR_RANK = 1ULL << PIR_LOG_RANK;
constexpr std::size_t DEFAULT_MAX_BODY_SIZE =
    std::numeric_limits<std::size_t>::max();
constexpr std::size_t STREAM_CHUNK_SIZE = 1ULL << 20; // 1 MiB chunks

Response makeBinaryResponse(const Request &req, std::vector<uint8_t> &&body) {
  Response res{http::status::ok, req.version()};
  res.set(http::field::content_type, "application/octet-stream");
  res.keep_alive(req.keep_alive());
  res.body() = std::move(body);
  res.prepare_payload();
  return res;
}

Response makeTextResponse(unsigned version, bool keep_alive,
                          http::status status,
                          const std::string &message) {
  Response res{status, version};
  res.set(http::field::content_type, "text/plain");
  res.keep_alive(keep_alive);
  res.body() = std::vector<uint8_t>(message.begin(), message.end());
  res.prepare_payload();
  return res;
}

Response makeTextResponse(const Request &req, http::status status,
                          const std::string &message) {
  return makeTextResponse(req.version(), req.keep_alive(), status, message);
}

} // namespace

struct HEVECServer::CollectionData {
  std::mutex mtx;
  std::unique_ptr<Server> server;
  SwitchingKey relinKey;
  AutedModPackKeys autedModPackKeys;
  AutedModPackMLWEKeys autedModPackMLWEKeys;

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
        autedModPackMLWEKeys(std::move(apmk)),
        pirInvAutKeys(std::move(piak)), dimension(d), metric_type(mt),
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

class HEVECServer::Session : public std::enable_shared_from_this<Session> {
public:
  Session(tcp::socket socket, HEVECServer &server)
      : socket_(std::move(socket)), server_(server) {}

  void start() { doRead(); }

private:
  tcp::socket socket_;
  HEVECServer &server_;
  boost::beast::flat_buffer buffer_;
  std::unique_ptr<http::request_parser<http::empty_body>> parser_;
  std::vector<uint8_t> body_buffer_;
  std::size_t expected_body_bytes_{0};
  std::size_t received_body_bytes_{0};
  std::array<uint8_t, STREAM_CHUNK_SIZE> body_chunk_buffer_{};
  std::shared_ptr<Response> response_;
  bool should_close_{false};
  const std::size_t max_body_size_{DEFAULT_MAX_BODY_SIZE};

  void doRead() {
    parser_ = std::make_unique<http::request_parser<http::empty_body>>();
    parser_->body_limit(std::numeric_limits<std::uint64_t>::max());
    expected_body_bytes_ = 0;
    received_body_bytes_ = 0;
    body_buffer_.clear();

    http::async_read_header(
        socket_, buffer_, *parser_,
        boost::beast::bind_front_handler(&Session::onReadHeader,
                                         shared_from_this()));
  }

  void onReadHeader(boost::beast::error_code ec, std::size_t) {
    if (ec == http::error::end_of_stream) {
      return doClose();
    }
    if (ec) {
      std::cerr << "HTTP read header error: " << ec.message() << std::endl;
      return;
    }

    if (parser_->chunked()) {
      return sendImmediateError(http::status::not_implemented,
                                "Chunked transfer encoding not supported");
    }

    auto content_length = parser_->content_length();
    if (content_length) {
      if (*content_length > max_body_size_ ||
          *content_length > std::numeric_limits<std::size_t>::max()) {
        return sendImmediateError(http::status::payload_too_large,
                                  "Request body exceeds server limit");
      }
      expected_body_bytes_ = static_cast<std::size_t>(*content_length);
      body_buffer_.reserve(expected_body_bytes_);
    } else {
      auto method = parser_->get().method();
      if (method == http::verb::post || method == http::verb::put ||
          method == http::verb::patch) {
        return sendImmediateError(http::status::length_required,
                                  "Content-Length header required");
      }
      expected_body_bytes_ = 0;
    }

    received_body_bytes_ += drainBufferedBody();

    if (received_body_bytes_ >= expected_body_bytes_) {
      finalizeRequest();
      return;
    }

    readBody();
  }

  std::size_t drainBufferedBody() {
    if (expected_body_bytes_ == 0) {
      return 0;
    }

    std::size_t copied = 0;
    auto data_seq = buffer_.data();
    std::size_t remaining = expected_body_bytes_ - received_body_bytes_;
    auto it =
        boost::asio::buffer_sequence_begin(data_seq);
    auto end_it =
        boost::asio::buffer_sequence_end(data_seq);
    for (; it != end_it && remaining > 0; ++it) {
      const auto &buf = *it;
      const auto *data_ptr = static_cast<const std::uint8_t *>(buf.data());
      const std::size_t buffer_size = buf.size();
      const std::size_t take = std::min(buffer_size, remaining);
      body_buffer_.insert(body_buffer_.end(), data_ptr, data_ptr + take);
      copied += take;
      remaining -= take;
      if (take < buffer_size) {
        break;
      }
    }

    buffer_.consume(copied);
    return copied;
  }

  void readBody() {
    const std::size_t remaining = expected_body_bytes_ - received_body_bytes_;
    if (remaining == 0) {
      finalizeRequest();
      return;
    }

    const std::size_t bytes_to_read =
        std::min<std::size_t>(STREAM_CHUNK_SIZE, remaining);
    auto self = shared_from_this();
    socket_.async_read_some(
        boost::asio::buffer(body_chunk_buffer_.data(), bytes_to_read),
        [self](boost::beast::error_code ec, std::size_t bytes_transferred) {
          self->onReadBodyChunk(ec, bytes_transferred);
        });
  }

  void onReadBodyChunk(boost::beast::error_code ec,
                       std::size_t bytes_transferred) {
    if (ec) {
      std::cerr << "HTTP body read error: " << ec.message() << std::endl;
      return doClose();
    }

    if (bytes_transferred == 0) {
      readBody();
      return;
    }

    body_buffer_.insert(body_buffer_.end(), body_chunk_buffer_.begin(),
                        body_chunk_buffer_.begin() + bytes_transferred);
    received_body_bytes_ += bytes_transferred;

    if (received_body_bytes_ >= expected_body_bytes_) {
      finalizeRequest();
    } else {
      readBody();
    }
  }

  void finalizeRequest() {
    auto base_req = parser_->release();
    parser_.reset();
    const unsigned version = base_req.version();
    const bool keep_alive = base_req.keep_alive();

    Request req{base_req.method(), base_req.target(), base_req.version()};
    req.base() = std::move(base_req.base());
    req.body() = std::move(body_buffer_);

    dispatchRequest(std::move(req), version, keep_alive);
  }

  void dispatchRequest(Request &&req, unsigned version, bool keep_alive) {
    HEVECServer::ResponseResult result;
    try {
      result = server_.processRequest(std::move(req));
    } catch (const std::exception &ex) {
      std::cerr << "Exception while handling request: " << ex.what()
                << std::endl;
      result.response = makeTextResponse(
          version, keep_alive, http::status::internal_server_error,
          "Internal server error");
      result.should_close = true;
    }

    writeResponse(std::move(result));
  }

  void writeResponse(HEVECServer::ResponseResult &&result) {
    should_close_ = result.should_close;
    response_ = std::make_shared<Response>(std::move(result.response));
    auto self = shared_from_this();
    http::async_write(
        socket_, *response_,
        [self](boost::beast::error_code write_ec, std::size_t) {
          self->onWrite(write_ec);
        });
  }

  void sendImmediateError(http::status status, const std::string &message) {
    auto &header = parser_->get();
    auto response = makeTextResponse(header.version(), header.keep_alive(),
                                     status, message);
    should_close_ = true;
    response_ = std::make_shared<Response>(std::move(response));
    auto self = shared_from_this();
    http::async_write(
        socket_, *response_,
        [self](boost::beast::error_code write_ec, std::size_t) {
          if (write_ec) {
            std::cerr << "HTTP write error: " << write_ec.message()
                      << std::endl;
          }
          self->doClose();
        });
  }

  void onWrite(boost::beast::error_code ec) {
    if (ec) {
      std::cerr << "HTTP write error: " << ec.message() << std::endl;
      return;
    }

    if (should_close_ || !response_->keep_alive()) {
      return doClose();
    }

    response_.reset();
    doRead();
  }

  void doClose() {
    boost::beast::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_send, ec);
    if (ec && ec != boost::system::errc::not_connected) {
      std::cerr << "Shutdown error: " << ec.message() << std::endl;
    }
  }
};

std::shared_ptr<HEVECServer::CollectionData>
HEVECServer::findCollection(u64 collectionHash) {
  std::lock_guard<std::mutex> lock(collections_mutex_);
  auto it = collections_.find(collectionHash);
  if (it == collections_.end()) {
    return nullptr;
  }
  return it->second;
}

std::shared_ptr<HEVECServer::CollectionData>
HEVECServer::getCollectionOrThrow(u64 collectionHash) {
  auto ctx = findCollection(collectionHash);
  if (!ctx) {
    throw std::runtime_error("Collection not found: " +
                             std::to_string(collectionHash));
  }
  return ctx;
}

HEVECServer::ResponseResult HEVECServer::processRequest(Request &&req) {
  HEVECServer::ResponseResult result;
  const std::string target(req.target());

  if (req.method() == http::verb::post) {
    if (target == "/collections/setup") {
      result.response = handleSetup(req);
    } else if (target == "/collections/insert") {
      result.response = handleInsert(req);
    } else if (target == "/collections/query") {
      result.response = handleQuery(req, true);
    } else if (target == "/collections/query_ptxt") {
      result.response = handleQuery(req, false);
    } else if (target == "/collections/retrieve") {
      result.response = handleRetrieve(req);
    } else if (target == "/collections/pir_retrieve") {
      result.response = handlePirRetrieve(req);
    } else if (target == "/terminate") {
      result.response = makeTextResponse(req, http::status::ok, "terminated");
      result.should_close = true;
    } else {
      result.response = makeTextResponse(req, http::status::not_found,
                                         "Unknown endpoint");
    }
    return result;
  }

  if (req.method() == http::verb::delete_) {
    constexpr std::string_view prefix = "/collections/";
    if (target.rfind(prefix, 0) == 0) {
      auto hash_str = target.substr(prefix.size());
      try {
        u64 collectionHash = std::stoull(hash_str);
        {
          std::lock_guard<std::mutex> lock(collections_mutex_);
          auto it = collections_.find(collectionHash);
          if (it != collections_.end()) {
            collections_.erase(it);
            logToFile("Collection " + std::to_string(collectionHash) +
                        " dropped successfully.");
          } else {
            logToFile("Failed to drop collection " +
                        std::to_string(collectionHash) + ": not found.");
          }
        }
        result.response = makeTextResponse(req, http::status::ok, "dropped");
      } catch (const std::exception &) {
        result.response = makeTextResponse(req, http::status::bad_request,
                                           "Invalid collection hash");
      }
      return result;
    }
  }

  result.response =
      makeTextResponse(req, http::status::method_not_allowed,
                       "Unsupported HTTP method");
  return result;
}

Response HEVECServer::handleSetup(const Request &req) {
  BinaryReader reader(req.body());
  u64 collectionHash = 0;
  u64 dimension = 0;
  MetricType metric_type = MetricType::COSINE;
  uint8_t has_keys = 0;

  if (!reader.read(collectionHash) || !reader.read(dimension) ||
      !reader.read(metric_type) || !reader.read(has_keys)) {
    return makeTextResponse(req, http::status::bad_request,
                            "Malformed setup request");
  }

  auto existing_ctx = findCollection(collectionHash);
  if (existing_ctx) {
    std::lock_guard<std::mutex> lock(existing_ctx->mtx);
    std::vector<uint8_t> body;
    if (existing_ctx->dimension != dimension) {
      uint8_t status = 2;
      appendBinary(body, status);
      appendBinary(body, existing_ctx->dimension);
      appendBinary(body, existing_ctx->metric_type);
      appendBinary(body, existing_ctx->db_size);
      std::cerr << "Collection " << collectionHash
                << " setup failed: Dimension mismatch. Got " << dimension
                << ", expected " << existing_ctx->dimension << std::endl;
      return makeBinaryResponse(req, std::move(body));
    }

    uint8_t status = 0;
    appendBinary(body, status);
    appendBinary(body, existing_ctx->dimension);
    appendBinary(body, existing_ctx->metric_type);
    appendBinary(body, existing_ctx->db_size);

    logToFile("Collection " + std::to_string(collectionHash) +
                " re-connected. DB size: " +
                std::to_string(existing_ctx->db_size));
    return makeBinaryResponse(req, std::move(body));
  }

  if (!has_keys) {
    std::vector<uint8_t> body;
    uint8_t status = 1;
    appendBinary(body, status);
    appendBinary(body, dimension);
    appendBinary(body, metric_type);
    u64 db_size = 0;
    appendBinary(body, db_size);
    return makeBinaryResponse(req, std::move(body));
  }

  if (dimension == 0 || dimension > DEGREE) {
    return makeTextResponse(req, http::status::bad_request,
                            "Invalid dimension value");
  }

  u64 log_rank = static_cast<u64>(std::ceil(std::log2(dimension)));
  u64 rank = 1ULL << log_rank;
  u64 stack = DEGREE / rank;

  SwitchingKey relinKey;
  AutedModPackKeys autedModPackKeys(rank);
  AutedModPackMLWEKeys autedModPackMLWEKeys(rank);
  InvAutKeys pirInvAutKeys(PIR_RANK);

  try {
    if (!reader.readBytes(relinKey.getPolyAModQ().getData(),
                          DEGREE * sizeof(u64)) ||
        !reader.readBytes(relinKey.getPolyAModP().getData(),
                          DEGREE * sizeof(u64)) ||
        !reader.readBytes(relinKey.getPolyBModQ().getData(),
                          DEGREE * sizeof(u64)) ||
        !reader.readBytes(relinKey.getPolyBModP().getData(),
                          DEGREE * sizeof(u64))) {
      throw std::runtime_error("Malformed relin key payload");
    }
    relinKey.getPolyAModQ().setIsNTT(true);
    relinKey.getPolyAModP().setIsNTT(true);
    relinKey.getPolyBModQ().setIsNTT(true);
    relinKey.getPolyBModP().setIsNTT(true);

    for (u64 i = 0; i < rank; ++i) {
      for (u64 j = 0; j < stack; ++j) {
        auto &key = autedModPackKeys.getKeys()[i][j];
        if (!reader.readBytes(key.getPolyAModQ().getData(),
                              DEGREE * sizeof(u64)) ||
            !reader.readBytes(key.getPolyAModP().getData(),
                              DEGREE * sizeof(u64)) ||
            !reader.readBytes(key.getPolyBModQ().getData(),
                              DEGREE * sizeof(u64)) ||
            !reader.readBytes(key.getPolyBModP().getData(),
                              DEGREE * sizeof(u64))) {
          throw std::runtime_error("Malformed autedModPack key payload");
        }
        key.getPolyAModQ().setIsNTT(true);
        key.getPolyAModP().setIsNTT(true);
        key.getPolyBModQ().setIsNTT(true);
        key.getPolyBModP().setIsNTT(true);
      }
    }

    for (u64 i = 0; i < rank; ++i) {
      for (u64 j = 0; j < stack; ++j) {
        auto &key = autedModPackMLWEKeys.getKeys()[i][j];
        for (u64 k = 0; k < stack; ++k) {
          if (!reader.readBytes(key.getPolyAModQ(k).getData(),
                                rank * sizeof(u64)) ||
              !reader.readBytes(key.getPolyAModP(k).getData(),
                                rank * sizeof(u64)) ||
              !reader.readBytes(key.getPolyBModQ(k).getData(),
                                rank * sizeof(u64)) ||
              !reader.readBytes(key.getPolyBModP(k).getData(),
                                rank * sizeof(u64))) {
            throw std::runtime_error(
                "Malformed autedModPackMLWE key payload");
          }
          key.getPolyAModQ(k).setIsNTT(true);
          key.getPolyAModP(k).setIsNTT(true);
          key.getPolyBModQ(k).setIsNTT(true);
          key.getPolyBModP(k).setIsNTT(true);
        }
      }
    }

    for (u64 i = 0; i < PIR_RANK; ++i) {
      auto &key = pirInvAutKeys.getKeys()[i];
      if (!reader.readBytes(key.getPolyAModQ().getData(),
                            DEGREE * sizeof(u64)) ||
          !reader.readBytes(key.getPolyAModP().getData(),
                            DEGREE * sizeof(u64)) ||
          !reader.readBytes(key.getPolyBModQ().getData(),
                            DEGREE * sizeof(u64)) ||
          !reader.readBytes(key.getPolyBModP().getData(),
                            DEGREE * sizeof(u64))) {
        throw std::runtime_error("Malformed PIR key payload");
      }
      key.getPolyAModQ().setIsNTT(true);
      key.getPolyAModP().setIsNTT(true);
      key.getPolyBModQ().setIsNTT(true);
      key.getPolyBModP().setIsNTT(true);
    }
  } catch (const std::exception &ex) {
    return makeTextResponse(req, http::status::bad_request, ex.what());
  }

  auto new_collection = std::make_shared<CollectionData>(
      dimension, metric_type, std::move(relinKey), std::move(autedModPackKeys),
      std::move(autedModPackMLWEKeys), std::move(pirInvAutKeys));

  {
    std::lock_guard<std::mutex> lock(collections_mutex_);
    collections_[collectionHash] = new_collection;
  }

  logToFile("Collection " + std::to_string(collectionHash) +
              " with dimension " + std::to_string(dimension) +
              " set up.");

  std::vector<uint8_t> body;
  uint8_t status = 0;
  appendBinary(body, status);
  appendBinary(body, dimension);
  appendBinary(body, metric_type);
  u64 db_size = 0;
  appendBinary(body, db_size);
  return makeBinaryResponse(req, std::move(body));
}

Response HEVECServer::handleInsert(const Request &req) {
  BinaryReader reader(req.body());
  u64 collectionHash = 0;
  u64 num_to_insert = 0;

  if (!reader.read(collectionHash) || !reader.read(num_to_insert)) {
    return makeTextResponse(req, http::status::bad_request,
                            "Malformed insert request");
  }

  auto ctx = getCollectionOrThrow(collectionHash);
  std::lock_guard<std::mutex> lock(ctx->mtx);

  Client pirClient(PIR_LOG_RANK);
  auto whole_start = std::chrono::high_resolution_clock::now();

  for (u64 i = 0; i < num_to_insert; ++i) {
    MLWECiphertext new_key(ctx->rank);
    for (u64 k = 0; k < ctx->stack; ++k) {
      if (!reader.readBytes(new_key.getA(k).getData(),
                            ctx->rank * sizeof(u64))) {
        return makeTextResponse(req, http::status::bad_request,
                                "Malformed key payload (A)");
      }
    }
    if (!reader.readBytes(new_key.getB().getData(),
                          ctx->rank * sizeof(u64))) {
      return makeTextResponse(req, http::status::bad_request,
                              "Malformed key payload (B)");
    }

    std::string payload(PIR_PAYLOAD_SIZE, '\0');
    if (!reader.readBytes(payload.data(), payload.size())) {
      return makeTextResponse(req, http::status::bad_request,
                              "Malformed payload data");
    }
    ctx->payloads_.push_back(payload);

    const unsigned char *payload_data =
        reinterpret_cast<const unsigned char *>(payload.data());
    pirClient.encodePIRPayload(
        ctx->pir_encoded_payloads_[ctx->db_size + i], payload_data);

    ctx->partial_block_keys_.push_back(std::move(new_key));

    if (ctx->partial_block_keys_.size() == DEGREE) {
      ctx->full_block_caches_.emplace_back(ctx->rank);
      auto start = std::chrono::high_resolution_clock::now();
      ctx->server->cacheKeys(ctx->full_block_caches_.back(),
                             ctx->partial_block_keys_);
      auto end = std::chrono::high_resolution_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
          end - start);
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
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start);
    logToFile("Cache partial block: " + std::to_string(duration.count()) +
              "ms");
  }

  ctx->db_size += num_to_insert;
  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);

  logToFile("Inserted " + std::to_string(num_to_insert) +
            " items into collection " + std::to_string(collectionHash) +
            ". Total DB size: " + std::to_string(ctx->db_size) +
            ". Took: " + std::to_string(whole_duration.count()) + "ms");

  return makeBinaryResponse(req, {});
}

Response HEVECServer::handleQuery(const Request &req, bool isEncrypted) {
  BinaryReader reader(req.body());
  u64 collectionHash = 0;
  if (!reader.read(collectionHash)) {
    return makeTextResponse(req, http::status::bad_request,
                            "Malformed query request");
  }

  auto ctx = getCollectionOrThrow(collectionHash);
  std::lock_guard<std::mutex> lock(ctx->mtx);

  auto whole_start = std::chrono::high_resolution_clock::now();
  std::vector<uint8_t> body;

  if (ctx->db_size == 0) {
    return makeTextResponse(req, http::status::bad_request,
                            "Collection is empty");
  }

  if (isEncrypted) {
    MLWECiphertext query(ctx->rank);
    CachedQuery queryCache(ctx->rank);

    for (u64 i = 0; i < ctx->stack; ++i) {
      if (!reader.readBytes(query.getA(i).getData(),
                            ctx->rank * sizeof(u64))) {
        return makeTextResponse(req, http::status::bad_request,
                                "Malformed query payload (A)");
      }
    }
    if (!reader.readBytes(query.getB().getData(),
                           ctx->rank * sizeof(u64))) {
      return makeTextResponse(req, http::status::bad_request,
                              "Malformed query payload (B)");
    }

    auto start = std::chrono::high_resolution_clock::now();
    ctx->server->cacheQuery(queryCache, query);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    logToFile("Cache query: " + std::to_string(duration.count()) + "ms");

    const u64 iter_full = ctx->full_block_caches_.size();
    auto total_inner_product_duration = std::chrono::milliseconds(0);

    for (u64 i = 0; i < iter_full; ++i) {
      Ciphertext res;
      start = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(res, queryCache, ctx->full_block_caches_[i]);
      end = std::chrono::high_resolution_clock::now();
      duration = std::chrono::duration_cast<std::chrono::milliseconds>(
          end - start);
      total_inner_product_duration += duration;

      appendBinary(body, res.getA().getData(), DEGREE * sizeof(u64));
      appendBinary(body, res.getB().getData(), DEGREE * sizeof(u64));
    }

    logToFile("Inner product for full blocks: " +
              std::to_string(total_inner_product_duration.count()) + "ms");

    if (ctx->partial_block_cache_) {
      Ciphertext partial_res;
      auto start_partial = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(partial_res, queryCache,
                                *ctx->partial_block_cache_);
      auto end_partial = std::chrono::high_resolution_clock::now();
      auto duration_partial =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              end_partial - start_partial);
      logToFile("Inner product for partial block: " +
                std::to_string(duration_partial.count()) + "ms");

      appendBinary(body, partial_res.getA().getData(), DEGREE * sizeof(u64));
      appendBinary(body, partial_res.getB().getData(), DEGREE * sizeof(u64));
    }
  } else {
    CachedPlaintextQuery queryCache(ctx->rank);
    Polynomial query(ctx->rank, MOD_Q);
    if (!reader.readBytes(query.getData(), ctx->rank * sizeof(u64))) {
      return makeTextResponse(req, http::status::bad_request,
                              "Malformed plaintext query payload");
    }
    query.setIsNTT(true);

    auto start = std::chrono::high_resolution_clock::now();
    ctx->server->cacheQuery(queryCache, query);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    logToFile("Cache plaintext query: " + std::to_string(duration.count()) +
              "ms");

    const u64 iter_full = ctx->full_block_caches_.size();
    auto total_inner_product_duration = std::chrono::milliseconds(0);

    for (u64 i = 0; i < iter_full; ++i) {
      Ciphertext res;
      start = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(res, queryCache, ctx->full_block_caches_[i]);
      end = std::chrono::high_resolution_clock::now();
      duration = std::chrono::duration_cast<std::chrono::milliseconds>(
          end - start);
      total_inner_product_duration += duration;

      appendBinary(body, res.getA().getData(), DEGREE * sizeof(u64));
      appendBinary(body, res.getB().getData(), DEGREE * sizeof(u64));
    }

    logToFile("Inner product for full blocks (plaintext): " +
              std::to_string(total_inner_product_duration.count()) + "ms");

    if (ctx->partial_block_cache_) {
      Ciphertext partial_res;
      auto start_partial = std::chrono::high_resolution_clock::now();
      ctx->server->innerProduct(partial_res, queryCache,
                                *ctx->partial_block_cache_);
      auto end_partial = std::chrono::high_resolution_clock::now();
      auto duration_partial =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              end_partial - start_partial);
      logToFile("Inner product for partial block (plaintext): " +
                std::to_string(duration_partial.count()) + "ms");

      appendBinary(body, partial_res.getA().getData(), DEGREE * sizeof(u64));
      appendBinary(body, partial_res.getB().getData(), DEGREE * sizeof(u64));
    }
  }

  auto whole_end = std::chrono::high_resolution_clock::now();
  auto whole_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      whole_end - whole_start);
  logToFile("Total query handling time: " +
            std::to_string(whole_duration.count()) + "ms");

  return makeBinaryResponse(req, std::move(body));
}

Response HEVECServer::handleRetrieve(const Request &req) {
  BinaryReader reader(req.body());
  u64 collectionHash = 0;
  u64 num_indices = 0;

  if (!reader.read(collectionHash) || !reader.read(num_indices)) {
    return makeTextResponse(req, http::status::bad_request,
                            "Malformed retrieve request");
  }

  auto ctx = getCollectionOrThrow(collectionHash);
  std::lock_guard<std::mutex> lock(ctx->mtx);

  std::vector<uint8_t> body;
  body.reserve(num_indices * PIR_PAYLOAD_SIZE);

  std::string empty_payload(PIR_PAYLOAD_SIZE, '\0');
  for (u64 i = 0; i < num_indices; ++i) {
    u64 index = 0;
    if (!reader.read(index)) {
      return makeTextResponse(req, http::status::bad_request,
                              "Malformed retrieve index");
    }
    if (index < ctx->db_size) {
      appendBinary(body, ctx->payloads_[index].data(), PIR_PAYLOAD_SIZE);
    } else {
      appendBinary(body, empty_payload.data(), PIR_PAYLOAD_SIZE);
    }
  }

  return makeBinaryResponse(req, std::move(body));
}

Response HEVECServer::handlePirRetrieve(const Request &req) {
  BinaryReader reader(req.body());
  u64 collectionHash = 0;
  if (!reader.read(collectionHash)) {
    return makeTextResponse(req, http::status::bad_request,
                            "Malformed PIR retrieve request");
  }

  auto ctx = getCollectionOrThrow(collectionHash);
  std::lock_guard<std::mutex> lock(ctx->mtx);

  if (ctx->db_size == 0) {
    throw std::runtime_error("Database is empty");
  }

  const u64 pir_db_size = PIR_RANK * PIR_RANK;
  if (ctx->db_size > pir_db_size) {
    throw std::runtime_error("Database size exceeds PIR capacity");
  }

  Ciphertext firstDim;
  Ciphertext secondDim;

  if (!reader.readBytes(firstDim.getA().getData(), DEGREE * sizeof(u64)) ||
      !reader.readBytes(firstDim.getB().getData(), DEGREE * sizeof(u64)) ||
      !reader.readBytes(secondDim.getA().getData(), DEGREE * sizeof(u64)) ||
      !reader.readBytes(secondDim.getB().getData(), DEGREE * sizeof(u64))) {
    return makeTextResponse(req, http::status::bad_request,
                            "Malformed PIR query payload");
  }

  PIRServer pirServer(PIR_LOG_RANK, ctx->relinKey, ctx->pirInvAutKeys);
  Ciphertext result;
  pirServer.pir(result, firstDim, secondDim, ctx->pir_encoded_payloads_);

  std::vector<uint8_t> body;
  appendBinary(body, result.getA().getData(), DEGREE * sizeof(u64));
  appendBinary(body, result.getB().getData(), DEGREE * sizeof(u64));
  return makeBinaryResponse(req, std::move(body));
}

HEVECServer::HEVECServer(unsigned short port)
    : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {
  doAccept();
}

void HEVECServer::run() { io_context_.run(); }

void HEVECServer::doAccept() {
  acceptor_.async_accept(
      [this](boost::beast::error_code ec, tcp::socket socket) {
        if (!ec) {
          std::make_shared<Session>(std::move(socket), *this)->start();
        } else {
          std::cerr << "Accept error: " << ec.message() << std::endl;
        }
        doAccept();
      });
}

} // namespace HEVEC
