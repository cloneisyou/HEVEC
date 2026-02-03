#pragma once

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "Type.hpp"

namespace HEVEC {

class HEVECServer {
public:
  explicit HEVECServer(unsigned short port);
  void run();

private:
  class Session;
  friend class Session;

  struct CollectionData;

  using HttpRequest =
      boost::beast::http::request<boost::beast::http::vector_body<uint8_t>>;
  using HttpResponse =
      boost::beast::http::response<boost::beast::http::vector_body<uint8_t>>;

  struct ResponseResult {
    HttpResponse response;
    bool should_close{false};
  };

  std::shared_ptr<CollectionData> findCollection(u64 collectionHash);
  std::shared_ptr<CollectionData> getCollectionOrThrow(u64 collectionHash);

  void doAccept();
  ResponseResult processRequest(HttpRequest &&req);
  HttpResponse handleSetup(const HttpRequest &req);
  HttpResponse handleInsert(const HttpRequest &req);
  HttpResponse handleQuery(const HttpRequest &req, bool isEncrypted);
  HttpResponse handleRetrieve(const HttpRequest &req);
  HttpResponse handlePirRetrieve(const HttpRequest &req);

  boost::asio::io_context io_context_;
  boost::asio::ip::tcp::acceptor acceptor_;

  std::unordered_map<u64, std::shared_ptr<CollectionData>> collections_;
  std::mutex collections_mutex_;
};

} // namespace HEVEC
