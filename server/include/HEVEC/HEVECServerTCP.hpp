#pragma once

#include <asio.hpp>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "Type.hpp"

namespace HEVEC {

using tcp = asio::ip::tcp;

class HEVECServerTCP {
public:
  HEVECServerTCP(unsigned short port);
  void run();

private:
  class Session;
  friend class Session;

  struct CollectionData;

  void doAccept();

  asio::io_context io_context_;
  tcp::acceptor acceptor_;

  std::unordered_map<u64, std::shared_ptr<CollectionData>> collections_;
  std::mutex collections_mutex_;
};

} // namespace HEVEC
