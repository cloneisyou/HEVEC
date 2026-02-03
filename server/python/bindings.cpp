#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Client.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/HEVECClient.hpp"
#include "HEVEC/HEVECServer.hpp"
#include "HEVEC/Keys.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/Message.hpp"
#include "HEVEC/MetricType.hpp"
#include "HEVEC/Polynomial.hpp"
#include "HEVEC/SecretKey.hpp"
#include "HEVEC/Server.hpp"
#include "HEVEC/SwitchingKey.hpp"
#include "HEVEC/TopK.hpp"
#include "HEVEC/Type.hpp"

namespace py = pybind11;

PYBIND11_MODULE(hevec_py, m) {
  m.doc() = "Python bindings for HEVEC library";

  py::enum_<HEVEC::MetricType>(m, "MetricType")
      .value("IP", HEVEC::MetricType::IP)
      .value("L2", HEVEC::MetricType::L2)
      .value("COSINE", HEVEC::MetricType::COSINE)
      .export_values();

  py::class_<HEVEC::Message>(m, "Message", py::buffer_protocol())
      .def(py::init<HEVEC::u64>())
      .def("get_degree", &HEVEC::Message::getDegree)
      .def_buffer([](HEVEC::Message &self) -> py::buffer_info {
        return py::buffer_info(static_cast<void *>(self.getData()),
                               sizeof(double),
                               py::format_descriptor<double>::format(), 1,
                               {self.getDegree()}, {sizeof(double)});
      })
      .def("__getitem__",
           [](const HEVEC::Message &self, std::size_t idx) { return self[idx]; })
      .def("__setitem__", [](HEVEC::Message &self, std::size_t idx,
                             double value) { self[idx] = value; });

  py::class_<HEVEC::Client>(m, "Client")
      .def(py::init<HEVEC::u64>())
      .def("gen_sec_key", &HEVEC::Client::genSecKey)
      .def("gen_relin_key", &HEVEC::Client::genRelinKey)
      .def("gen_auted_mod_pack_keys", &HEVEC::Client::genAutedModPackKeys)
      .def("gen_inv_auted_mod_pack_keys", &HEVEC::Client::genInvAutedModPackKeys)
      .def("encrypt_query", &HEVEC::Client::encryptQuery)
      .def("encrypt_key", &HEVEC::Client::encryptKey)
      .def("encode", &HEVEC::Client::encode)
      .def("decode", &HEVEC::Client::decode)
      .def("encrypt",
           py::overload_cast<HEVEC::Ciphertext &, const HEVEC::Polynomial &,
                             const HEVEC::SecretKey &>(&HEVEC::Client::encrypt))
      .def("encrypt", py::overload_cast<HEVEC::Ciphertext &, const HEVEC::Message &,
                                        const HEVEC::SecretKey &, double>(
                          &HEVEC::Client::encrypt))
      .def("decrypt", &HEVEC::Client::decrypt)
      .def("decrypt_score", &HEVEC::Client::decryptScore)
      .def("top_k_score",
           py::overload_cast<HEVEC::TopK &, const std::vector<HEVEC::Message> &>(
               &HEVEC::Client::topKScore))
      .def("get_rank", &HEVEC::Client::getRank)
      .def("get_inv_rank", &HEVEC::Client::getInvRank);

  py::class_<HEVEC::MLWECiphertext>(m, "MLWECiphertext")
      .def(py::init<HEVEC::u64>())
      .def(
          "get_a",
          [](HEVEC::MLWECiphertext &self, HEVEC::u64 idx) -> HEVEC::Polynomial & {
            return self.getA(idx);
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_b",
          [](HEVEC::MLWECiphertext &self) -> HEVEC::Polynomial & {
            return self.getB();
          },
          py::return_value_policy::reference_internal);

  // SwitchingKey bindings
  py::class_<HEVEC::SwitchingKey>(m, "SwitchingKey")
      .def(py::init<>())
      .def(
          "get_poly_a_mod_q",
          [](HEVEC::SwitchingKey &self) -> HEVEC::Polynomial & {
            return self.getPolyAModQ();
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_a_mod_p",
          [](HEVEC::SwitchingKey &self) -> HEVEC::Polynomial & {
            return self.getPolyAModP();
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_b_mod_q",
          [](HEVEC::SwitchingKey &self) -> HEVEC::Polynomial & {
            return self.getPolyBModQ();
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_b_mod_p",
          [](HEVEC::SwitchingKey &self) -> HEVEC::Polynomial & {
            return self.getPolyBModP();
          },
          py::return_value_policy::reference_internal);

  // MLWESwitchingKey bindings
  py::class_<HEVEC::MLWESwitchingKey>(m, "MLWESwitchingKey")
      .def(py::init<HEVEC::u64>())
      .def(
          "get_poly_a_mod_q",
          [](HEVEC::MLWESwitchingKey &self, HEVEC::u64 idx) -> HEVEC::Polynomial & {
            return self.getPolyAModQ(idx);
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_a_mod_p",
          [](HEVEC::MLWESwitchingKey &self, HEVEC::u64 idx) -> HEVEC::Polynomial & {
            return self.getPolyAModP(idx);
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_b_mod_q",
          [](HEVEC::MLWESwitchingKey &self, HEVEC::u64 idx) -> HEVEC::Polynomial & {
            return self.getPolyBModQ(idx);
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_b_mod_p",
          [](HEVEC::MLWESwitchingKey &self, HEVEC::u64 idx) -> HEVEC::Polynomial & {
            return self.getPolyBModP(idx);
          },
          py::return_value_policy::reference_internal);

  // AutedModPackKeys bindings
  py::class_<HEVEC::AutedModPackKeys>(m, "AutedModPackKeys")
      .def(py::init<HEVEC::u64>())
      .def(
          "get_key",
          [](HEVEC::AutedModPackKeys &self, HEVEC::u64 i, HEVEC::u64 j)
              -> HEVEC::SwitchingKey & { return self.getKeys()[i][j]; },
          py::return_value_policy::reference_internal);

  // AutedModPackMLWEKeys bindings
  py::class_<HEVEC::AutedModPackMLWEKeys>(m, "AutedModPackMLWEKeys")
      .def(py::init<HEVEC::u64>())
      .def(
          "get_key",
          [](HEVEC::AutedModPackMLWEKeys &self, HEVEC::u64 i, HEVEC::u64 j)
              -> HEVEC::MLWESwitchingKey & { return self.getKeys()[i][j]; },
          py::return_value_policy::reference_internal);

  // CachedQuery bindings
  py::class_<HEVEC::CachedQuery>(m, "CachedQuery").def(py::init<HEVEC::u64>());

  // CachedKeys bindings
  py::class_<HEVEC::CachedKeys>(m, "CachedKeys").def(py::init<HEVEC::u64>());

  // Server bindings
  py::class_<HEVEC::Server>(m, "Server")
      .def(py::init<HEVEC::u64, const HEVEC::SwitchingKey &,
                    const HEVEC::AutedModPackKeys &,
                    const HEVEC::AutedModPackMLWEKeys &>())
      .def("cache_query",
           [](HEVEC::Server &self, HEVEC::CachedQuery &cache,
              const HEVEC::MLWECiphertext &query) {
             self.cacheQuery(cache, query);
           })
      .def("cache_keys",
           [](HEVEC::Server &self, HEVEC::CachedKeys &cache,
              const std::vector<HEVEC::MLWECiphertext> &keys) {
             self.cacheKeys(cache, keys);
           })
      .def("inner_product", [](HEVEC::Server &self, HEVEC::Ciphertext &res,
                               const HEVEC::CachedQuery &query_cache,
                               const HEVEC::CachedKeys &key_cache) {
        self.innerProduct(res, query_cache, key_cache);
      });

  // Polynomial bindings
  py::class_<HEVEC::Polynomial>(m, "Polynomial", py::buffer_protocol())
      .def(py::init<HEVEC::u64, HEVEC::u64>())
      .def("get_degree", &HEVEC::Polynomial::getDegree)
      .def("get_mod", &HEVEC::Polynomial::getMod)
      .def("get_is_ntt", &HEVEC::Polynomial::getIsNTT)
      .def("set_is_ntt", &HEVEC::Polynomial::setIsNTT)
      .def_buffer([](HEVEC::Polynomial &self) -> py::buffer_info {
        return py::buffer_info(
            static_cast<void *>(self.getData()),       // Pointer to buffer
            sizeof(HEVEC::u64),                          // Size of one scalar
            py::format_descriptor<HEVEC::u64>::format(), // Python struct-style
                                                       // format descriptor
            1,                                         // Number of dimensions
            {self.getDegree()},                        // Buffer dimensions
            {sizeof(HEVEC::u64)} // Strides (in bytes) for each index
        );
      })
      .def("__getitem__", [](const HEVEC::Polynomial &self,
                             std::size_t idx) { return self[idx]; })
      .def("__setitem__", [](HEVEC::Polynomial &self, std::size_t idx,
                             HEVEC::u64 value) { self[idx] = value; });

  // SecretKey bindings
  py::class_<HEVEC::SecretKey>(m, "SecretKey")
      .def(py::init<>())
      .def(
          "get_poly_q",
          [](HEVEC::SecretKey &self) -> HEVEC::Polynomial & {
            return self.getPolyQ();
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_poly_p",
          [](HEVEC::SecretKey &self) -> HEVEC::Polynomial & {
            return self.getPolyP();
          },
          py::return_value_policy::reference_internal);

  // Ciphertext bindings
  py::class_<HEVEC::Ciphertext>(m, "Ciphertext")
      .def(py::init<bool>(), py::arg("is_extended") = false)
      .def("set_is_ntt", &HEVEC::Ciphertext::setIsNTT)
      .def("get_degree", &HEVEC::Ciphertext::getDegree)
      .def("get_is_extended", &HEVEC::Ciphertext::getIsExtended)
      .def("get_is_ntt", &HEVEC::Ciphertext::getIsNTT)
      .def(
          "get_a",
          [](HEVEC::Ciphertext &self) -> HEVEC::Polynomial & {
            return self.getA();
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_b",
          [](HEVEC::Ciphertext &self) -> HEVEC::Polynomial & {
            return self.getB();
          },
          py::return_value_policy::reference_internal)
      .def(
          "get_c",
          [](HEVEC::Ciphertext &self) -> HEVEC::Polynomial & {
            return self.getC();
          },
          py::return_value_policy::reference_internal);

  // TopK bindings
  py::class_<HEVEC::TopK>(m, "TopK")
      .def(py::init<size_t>())
      .def("__getitem__",
           [](const HEVEC::TopK &self, size_t i) { return self[i]; })
      .def("__setitem__", [](HEVEC::TopK &self, size_t i, int v) { self[i] = v; })
      .def("__len__", &HEVEC::TopK::size);

  // HEVECClient bindings
  py::class_<HEVEC::HEVECClient>(m, "HEVECClient")
      .def(py::init<const std::string &, const std::string &>(),
           py::arg("host"), py::arg("port"))
      .def("setup_collection", &HEVEC::HEVECClient::setupCollection,
           py::arg("collection_name"), py::arg("dimension"),
           py::arg("metric_type"), py::arg("is_query_encrypt") = true)
      .def("drop_collection", &HEVEC::HEVECClient::dropCollection,
           py::arg("collection_name"))
      .def("terminate", &HEVEC::HEVECClient::terminate)
      .def(
          "insert",
          [](HEVEC::HEVECClient &self, const std::string &collectionName,
             py::array_t<float, py::array::c_style | py::array::forcecast> db,
             const std::vector<std::string> &payloads) {
            if (db.ndim() != 2) {
              throw std::runtime_error("Input database must be a 2D array.");
            }
            if (static_cast<size_t>(db.shape(0)) != payloads.size()) {
              throw std::runtime_error(
                  "Input database and payloads must have the same number of "
                  "entries.");
            }
            std::vector<std::vector<float>> cpp_db(db.shape(0));
            for (ssize_t i = 0; i < db.shape(0); ++i) {
              cpp_db[i].resize(db.shape(1));
              for (ssize_t j = 0; j < db.shape(1); ++j) {
                cpp_db[i][j] = *db.data(i, j);
              }
            }
            self.insert(collectionName, cpp_db, payloads);
          },
          py::arg("collection_name"), py::arg("db"), py::arg("payloads"))
      .def(
          "query",
          [](HEVEC::HEVECClient &self, const std::string &collectionName,
             py::array_t<float, py::array::c_style | py::array::forcecast>
                 query_vec) {
            if (query_vec.ndim() != 1) {
              throw std::runtime_error("Input query must be a 1D array.");
            }
            std::vector<float> cpp_query_vec(query_vec.size());
            for (ssize_t i = 0; i < query_vec.size(); ++i) {
              cpp_query_vec[i] = *query_vec.data(i);
            }
            std::vector<float> result_vec =
                self.query(collectionName, cpp_query_vec);
            return py::cast(result_vec);
          },
          py::arg("collection_name"), py::arg("query_vec"))
      .def(
          "query_and_top_k",
          [](HEVEC::HEVECClient &self, HEVEC::TopK &res,
             const std::string &collectionName,
             py::array_t<float, py::array::c_style | py::array::forcecast>
                 query_vec) {
            if (query_vec.ndim() != 1) {
              throw std::runtime_error("Input query must be a 1D array.");
            }
            std::vector<float> cpp_query_vec(query_vec.size());
            for (ssize_t i = 0; i < query_vec.size(); ++i) {
              cpp_query_vec[i] = *query_vec.data(i);
            }
            self.queryAndTopK(res, collectionName, cpp_query_vec);
          },
          py::arg("res"), py::arg("collection_name"), py::arg("query_vec"))
      .def(
          "query_and_top_k_with_scores",
          [](HEVEC::HEVECClient &self, const std::string &collectionName,
             py::array_t<float, py::array::c_style | py::array::forcecast>
                 query_vec,
             HEVEC::u64 k) {
            if (query_vec.ndim() != 1) {
              throw std::runtime_error("Input query must be a 1D array.");
            }
            std::vector<float> cpp_query_vec(query_vec.size());
            for (ssize_t i = 0; i < query_vec.size(); ++i) {
              cpp_query_vec[i] = *query_vec.data(i);
            }
            std::vector<std::pair<HEVEC::u64, float>> results;
            self.queryAndTopKWithScores(results, collectionName, cpp_query_vec,
                                        k);

            // Convert to Python-friendly format
            py::list py_results;
            for (const auto &pair : results) {
              py_results.append(py::make_tuple(pair.first, pair.second));
            }
            return py_results;
          },
          py::arg("collection_name"), py::arg("query_vec"), py::arg("k"))
      .def_static(
          "get_top_k_indices",
          [](py::array_t<float, py::array::c_style | py::array::forcecast>
                 scores,
             HEVEC::u64 k) {
            if (scores.ndim() != 1) {
              throw std::runtime_error("Input scores must be a 1D array.");
            }
            std::vector<float> cpp_scores(scores.size());
            for (ssize_t i = 0; i < scores.size(); ++i) {
              cpp_scores[i] = *scores.data(i);
            }
            std::vector<HEVEC::u64> results =
                HEVEC::HEVECClient::getTopKIndices(cpp_scores, k);
            return py::cast(results);
          },
          py::arg("scores"), py::arg("k"))
      .def("retrieve", &HEVEC::HEVECClient::retrieve, py::arg("collection_name"),
           py::arg("index"))
      .def("retrieve_pir", &HEVEC::HEVECClient::retrievePIR,
           py::arg("collection_name"), py::arg("index"));

  // HEVECServer bindings
  py::class_<HEVEC::HEVECServer>(m, "HEVECServer")
      .def(py::init<unsigned short>(), py::arg("port"))
      .def("run", &HEVEC::HEVECServer::run,
           py::call_guard<py::gil_scoped_release>());
}
