#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <napi.h>

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Client.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/HEVECClient.hpp"
#include "HEVEC/Keys.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/MLWESwitchingKey.hpp"
#include "HEVEC/Message.hpp"
#include "HEVEC/MetricType.hpp"
#include "HEVEC/Polynomial.hpp"
#include "HEVEC/SecretKey.hpp"
#include "HEVEC/Server.hpp"
#include "HEVEC/SwitchingKey.hpp"
#include "HEVEC/TopK.hpp"
#include "HEVEC/Type.hpp"

namespace {

void NoopFinalizer(Napi::Env /*env*/, void * /*data*/) {}

template <typename T = HEVEC::u64>
T RequireUint(const Napi::Env &env, const Napi::Value &value,
              const char *name) {
  if (value.IsBigInt()) {
    bool lossless = false;
    auto raw = value.As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
      Napi::TypeError::New(env, std::string(name) + " exceeds 64-bit range")
          .ThrowAsJavaScriptException();
      return 0;
    }
    return static_cast<T>(raw);
  }
  if (!value.IsNumber()) {
    Napi::TypeError::New(env, std::string(name) + " must be a number")
        .ThrowAsJavaScriptException();
    return 0;
  }
  double dbl = value.As<Napi::Number>().DoubleValue();
  if (dbl < 0) {
    Napi::TypeError::New(env, std::string(name) + " must be non-negative")
        .ThrowAsJavaScriptException();
    return 0;
  }
  return static_cast<T>(dbl);
}

size_t RequireIndex(const Napi::Env &env, const Napi::Value &value,
                    const char *name) {
  return RequireUint<size_t>(env, value, name);
}

double RequireNumber(const Napi::Env &env, const Napi::Value &value,
                     const char *name) {
  if (!value.IsNumber()) {
    Napi::TypeError::New(env, std::string(name) + " must be a number")
        .ThrowAsJavaScriptException();
    return 0.0;
  }
  return value.As<Napi::Number>().DoubleValue();
}

std::vector<float> RequireFloatVector(const Napi::Env &env,
                                      const Napi::Value &value,
                                      const char *name) {
  if (value.IsTypedArray()) {
    Napi::TypedArray arr = value.As<Napi::TypedArray>();
    napi_typedarray_type type = arr.TypedArrayType();
    if (type != napi_float32_array && type != napi_float64_array) {
      Napi::TypeError::New(
          env, std::string(name) + " must be Float32Array or Float64Array")
          .ThrowAsJavaScriptException();
      return {};
    }
    std::vector<float> result(arr.ElementLength());
    if (type == napi_float32_array) {
      auto f32 = arr.As<Napi::Float32Array>();
      for (size_t i = 0; i < result.size(); ++i) {
        result[i] = f32[i];
      }
    } else {
      auto f64 = arr.As<Napi::Float64Array>();
      for (size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<float>(f64[i]);
      }
    }
    return result;
  }
  if (!value.IsArray()) {
    Napi::TypeError::New(env,
                         std::string(name) + " must be an array or typed array")
        .ThrowAsJavaScriptException();
    return {};
  }
  Napi::Array arr = value.As<Napi::Array>();
  std::vector<float> result(arr.Length());
  for (size_t i = 0; i < arr.Length(); ++i) {
    result[i] =
        static_cast<float>(RequireNumber(env, arr.Get(i), "vector element"));
  }
  return result;
}

std::vector<std::vector<float>>
RequireFloatMatrix(const Napi::Env &env, const Napi::Value &value,
                   const char *name) {
  if (!value.IsArray()) {
    Napi::TypeError::New(env, std::string(name) + " must be an array")
        .ThrowAsJavaScriptException();
    return {};
  }
  Napi::Array arr = value.As<Napi::Array>();
  std::vector<std::vector<float>> matrix;
  matrix.reserve(arr.Length());
  for (size_t i = 0; i < arr.Length(); ++i) {
    std::vector<float> row =
        RequireFloatVector(env, arr.Get(i), "matrix row");
    matrix.push_back(std::move(row));
  }
  return matrix;
}

template <typename T>
T *Unwrap(const Napi::CallbackInfo &info, size_t index,
          const char *expected_name) {
  if (info.Length() <= index || !info[index].IsObject()) {
    Napi::TypeError::New(
        info.Env(), std::string("Expected ") + expected_name + " at argument " +
                        std::to_string(index))
        .ThrowAsJavaScriptException();
    return nullptr;
  }
  return Napi::ObjectWrap<T>::Unwrap(info[index].As<Napi::Object>())->Get();
}

class MessageWrap : public Napi::ObjectWrap<MessageWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "Message",
                    {
                        InstanceMethod("getDegree", &MessageWrap::GetDegree),
                        InstanceMethod("get", &MessageWrap::GetItem),
                        InstanceMethod("set", &MessageWrap::SetItem),
                        InstanceMethod("asTypedArray", &MessageWrap::AsArray),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("Message", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::Message *msg,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::Message>::New(env, msg));
    args.push_back(Napi::Boolean::New(env, false));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  MessageWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<MessageWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      message_ = info[0].As<Napi::External<HEVEC::Message>>().Data();
      bool owned =
          info.Length() >= 2 && info[1].IsBoolean()
              ? info[1].As<Napi::Boolean>().Value()
              : false;
      if (owned) {
        owned_.reset(message_);
      }
      if (info.Length() >= 3 && info[2].IsObject()) {
        parentRef_ = Napi::Persistent(info[2].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(), "Message(degree) requires one argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto degree = RequireUint<HEVEC::u64>(info.Env(), info[0], "degree");
    owned_ = std::make_unique<HEVEC::Message>(degree);
    message_ = owned_.get();
  }

  ~MessageWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::Message *Get() { return message_; }

private:
  Napi::Value GetDegree(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(),
                             static_cast<double>(message_->getDegree()));
  }

  Napi::Value GetItem(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    if (idx >= message_->getDegree()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    return Napi::Number::New(info.Env(), (*message_)[idx]);
  }

  void SetItem(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    double value = RequireNumber(info.Env(), info[1], "value");
    if (idx >= message_->getDegree()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return;
    }
    (*message_)[idx] = value;
  }

  Napi::Value AsArray(const Napi::CallbackInfo &info) {
    auto env = info.Env();
    size_t byteLength = sizeof(double) * message_->getDegree();
    Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(
        env, message_->getData(), byteLength, NoopFinalizer);
    return Napi::Float64Array::New(env, message_->getDegree(), buffer, 0);
  }

  std::unique_ptr<HEVEC::Message> owned_;
  HEVEC::Message *message_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference MessageWrap::constructor;

class PolynomialWrap : public Napi::ObjectWrap<PolynomialWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "Polynomial",
                    {
                        InstanceMethod("getDegree", &PolynomialWrap::GetDegree),
                        InstanceMethod("getMod", &PolynomialWrap::GetMod),
                        InstanceMethod("getIsNTT", &PolynomialWrap::GetIsNTT),
                        InstanceMethod("setIsNTT", &PolynomialWrap::SetIsNTT),
                        InstanceMethod("get", &PolynomialWrap::GetItem),
                        InstanceMethod("set", &PolynomialWrap::SetItem),
                        InstanceMethod("asTypedArray", &PolynomialWrap::AsArray),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("Polynomial", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::Polynomial *poly,
                                  bool owned,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::Polynomial>::New(env, poly));
    args.push_back(Napi::Boolean::New(env, owned));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  PolynomialWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<PolynomialWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      poly_ = info[0].As<Napi::External<HEVEC::Polynomial>>().Data();
      bool owned =
          info.Length() >= 2 && info[1].IsBoolean()
              ? info[1].As<Napi::Boolean>().Value()
              : false;
      if (owned) {
        owned_.reset(poly_);
      }
      if (info.Length() >= 3 && info[2].IsObject()) {
        parentRef_ = Napi::Persistent(info[2].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 2) {
      Napi::TypeError::New(info.Env(),
                           "Polynomial(degree, mod) requires two arguments")
          .ThrowAsJavaScriptException();
      return;
    }
    auto degree = RequireUint<HEVEC::u64>(info.Env(), info[0], "degree");
    auto mod = RequireUint<HEVEC::u64>(info.Env(), info[1], "mod");
    owned_ = std::make_unique<HEVEC::Polynomial>(degree, mod);
    poly_ = owned_.get();
  }

  ~PolynomialWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::Polynomial *Get() { return poly_; }

private:
  Napi::Value GetDegree(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(),
                             static_cast<double>(poly_->getDegree()));
  }

  Napi::Value GetMod(const Napi::CallbackInfo &info) {
    return Napi::BigInt::New(info.Env(), poly_->getMod());
  }

  Napi::Value GetIsNTT(const Napi::CallbackInfo &info) {
    return Napi::Boolean::New(info.Env(), poly_->getIsNTT());
  }

  void SetIsNTT(const Napi::CallbackInfo &info) {
    if (info.Length() < 1 || !info[0].IsBoolean()) {
      Napi::TypeError::New(info.Env(), "Expected boolean").ThrowAsJavaScriptException();
      return;
    }
    poly_->setIsNTT(info[0].As<Napi::Boolean>().Value());
  }

  Napi::Value GetItem(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    if (idx >= poly_->getDegree()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    return Napi::BigInt::New(info.Env(), (*poly_)[idx]);
  }

  void SetItem(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    auto value = RequireUint<HEVEC::u64>(info.Env(), info[1], "value");
    if (idx >= poly_->getDegree()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return;
    }
    (*poly_)[idx] = value;
  }

  Napi::Value AsArray(const Napi::CallbackInfo &info) {
    auto env = info.Env();
    size_t byteLength = sizeof(HEVEC::u64) * poly_->getDegree();
    Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(
        env, poly_->getData(), byteLength, NoopFinalizer);
    return Napi::BigUint64Array::New(env, poly_->getDegree(), buffer, 0);
  }

  std::unique_ptr<HEVEC::Polynomial> owned_;
  HEVEC::Polynomial *poly_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference PolynomialWrap::constructor;

class SecretKeyWrap : public Napi::ObjectWrap<SecretKeyWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "SecretKey",
                    {InstanceMethod("getPolyQ", &SecretKeyWrap::GetPolyQ),
                     InstanceMethod("getPolyP", &SecretKeyWrap::GetPolyP)});
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("SecretKey", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::SecretKey *key) {
    return constructor.New(
        {Napi::External<HEVEC::SecretKey>::New(env, key)});
  }

  SecretKeyWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<SecretKeyWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      key_ = info[0].As<Napi::External<HEVEC::SecretKey>>().Data();
      return;
    }
    keyOwned_ = std::make_unique<HEVEC::SecretKey>();
    key_ = keyOwned_.get();
  }

  HEVEC::SecretKey *Get() { return key_; }

private:
  Napi::Value GetPolyQ(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyQ(), false,
                                       info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyP(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyP(), false,
                                       info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::SecretKey> keyOwned_;
  HEVEC::SecretKey *key_{nullptr};
};

Napi::FunctionReference SecretKeyWrap::constructor;

class SwitchingKeyWrap : public Napi::ObjectWrap<SwitchingKeyWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "SwitchingKey",
                    {
                        InstanceMethod("getPolyAModQ",
                                       &SwitchingKeyWrap::GetPolyAModQ),
                        InstanceMethod("getPolyAModP",
                                       &SwitchingKeyWrap::GetPolyAModP),
                        InstanceMethod("getPolyBModQ",
                                       &SwitchingKeyWrap::GetPolyBModQ),
                        InstanceMethod("getPolyBModP",
                                       &SwitchingKeyWrap::GetPolyBModP),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("SwitchingKey", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::SwitchingKey *key,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::SwitchingKey>::New(env, key));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  SwitchingKeyWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<SwitchingKeyWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      key_ = info[0].As<Napi::External<HEVEC::SwitchingKey>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    owned_ = std::make_unique<HEVEC::SwitchingKey>();
    key_ = owned_.get();
  }

  ~SwitchingKeyWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::SwitchingKey *Get() { return key_; }

private:
  Napi::Value GetPolyAModQ(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyAModQ(), false,
                                       info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyAModP(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyAModP(), false,
                                       info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyBModQ(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyBModQ(), false,
                                       info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyBModP(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyBModP(), false,
                                       info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::SwitchingKey> owned_;
  HEVEC::SwitchingKey *key_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference SwitchingKeyWrap::constructor;

class MLWESwitchingKeyWrap : public Napi::ObjectWrap<MLWESwitchingKeyWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "MLWESwitchingKey",
                    {
                        InstanceMethod("getPolyAModQ",
                                       &MLWESwitchingKeyWrap::GetPolyAModQ),
                        InstanceMethod("getPolyAModP",
                                       &MLWESwitchingKeyWrap::GetPolyAModP),
                        InstanceMethod("getPolyBModQ",
                                       &MLWESwitchingKeyWrap::GetPolyBModQ),
                        InstanceMethod("getPolyBModP",
                                       &MLWESwitchingKeyWrap::GetPolyBModP),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("MLWESwitchingKey", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::MLWESwitchingKey *key,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::MLWESwitchingKey>::New(env, key));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  MLWESwitchingKeyWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<MLWESwitchingKeyWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      key_ = info[0].As<Napi::External<HEVEC::MLWESwitchingKey>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(),
                           "MLWESwitchingKey(rank) requires rank argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto rank = RequireUint<HEVEC::u64>(info.Env(), info[0], "rank");
    owned_ = std::make_unique<HEVEC::MLWESwitchingKey>(rank);
    key_ = owned_.get();
  }

  ~MLWESwitchingKeyWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::MLWESwitchingKey *Get() { return key_; }

private:
  Napi::Value GetPolyAModQ(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyAModQ(idx),
                                       false, info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyAModP(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyAModP(idx),
                                       false, info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyBModQ(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyBModQ(idx),
                                       false, info.This().As<Napi::Object>());
  }
  Napi::Value GetPolyBModP(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    return PolynomialWrap::NewExternal(info.Env(), &key_->getPolyBModP(idx),
                                       false, info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::MLWESwitchingKey> owned_;
  HEVEC::MLWESwitchingKey *key_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference MLWESwitchingKeyWrap::constructor;

class AutedModPackKeysWrap : public Napi::ObjectWrap<AutedModPackKeysWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "AutedModPackKeys",
                    {InstanceMethod("getKey", &AutedModPackKeysWrap::GetKey)});
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("AutedModPackKeys", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::AutedModPackKeys *keys,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::AutedModPackKeys>::New(env, keys));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  AutedModPackKeysWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<AutedModPackKeysWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      keys_ = info[0].As<Napi::External<HEVEC::AutedModPackKeys>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(),
                           "AutedModPackKeys(rank) requires rank argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto rank = RequireUint<HEVEC::u64>(info.Env(), info[0], "rank");
    owned_ = std::make_unique<HEVEC::AutedModPackKeys>(rank);
    keys_ = owned_.get();
  }

  ~AutedModPackKeysWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::AutedModPackKeys *Get() { return keys_; }

private:
  Napi::Value GetKey(const Napi::CallbackInfo &info) {
    auto i = RequireIndex(info.Env(), info[0], "i");
    auto j = RequireIndex(info.Env(), info[1], "j");
    auto &vec = keys_->getKeys();
    if (i >= vec.size() || j >= vec[i].size()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    return SwitchingKeyWrap::NewExternal(info.Env(), &vec[i][j],
                                         info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::AutedModPackKeys> owned_;
  HEVEC::AutedModPackKeys *keys_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference AutedModPackKeysWrap::constructor;

class AutedModPackMLWEKeysWrap
    : public Napi::ObjectWrap<AutedModPackMLWEKeysWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "AutedModPackMLWEKeys",
        {InstanceMethod("getKey", &AutedModPackMLWEKeysWrap::GetKey)});
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("AutedModPackMLWEKeys", func);
  }

  static Napi::Object NewExternal(Napi::Env env,
                                  HEVEC::AutedModPackMLWEKeys *keys,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::AutedModPackMLWEKeys>::New(env, keys));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  AutedModPackMLWEKeysWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<AutedModPackMLWEKeysWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      keys_ = info[0].As<Napi::External<HEVEC::AutedModPackMLWEKeys>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(),
                           "AutedModPackMLWEKeys(rank) requires rank argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto rank = RequireUint<HEVEC::u64>(info.Env(), info[0], "rank");
    owned_ = std::make_unique<HEVEC::AutedModPackMLWEKeys>(rank);
    keys_ = owned_.get();
  }

  ~AutedModPackMLWEKeysWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::AutedModPackMLWEKeys *Get() { return keys_; }

private:
  Napi::Value GetKey(const Napi::CallbackInfo &info) {
    auto i = RequireIndex(info.Env(), info[0], "i");
    auto j = RequireIndex(info.Env(), info[1], "j");
    auto &vec = keys_->getKeys();
    if (i >= vec.size() || j >= vec[i].size()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    return MLWESwitchingKeyWrap::NewExternal(info.Env(), &vec[i][j],
                                             info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::AutedModPackMLWEKeys> owned_;
  HEVEC::AutedModPackMLWEKeys *keys_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference AutedModPackMLWEKeysWrap::constructor;

class CiphertextWrap : public Napi::ObjectWrap<CiphertextWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "Ciphertext",
                    {
                        InstanceMethod("setIsNTT", &CiphertextWrap::SetIsNTT),
                        InstanceMethod("getDegree", &CiphertextWrap::GetDegree),
                        InstanceMethod("getIsExtended",
                                       &CiphertextWrap::GetIsExtended),
                        InstanceMethod("getIsNTT", &CiphertextWrap::GetIsNTT),
                        InstanceMethod("getA", &CiphertextWrap::GetA),
                        InstanceMethod("getB", &CiphertextWrap::GetB),
                        InstanceMethod("getC", &CiphertextWrap::GetC),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("Ciphertext", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::Ciphertext *ctxt,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::Ciphertext>::New(env, ctxt));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  CiphertextWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<CiphertextWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      ctxt_ = info[0].As<Napi::External<HEVEC::Ciphertext>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    bool isExtended = false;
    if (info.Length() >= 1 && info[0].IsBoolean()) {
      isExtended = info[0].As<Napi::Boolean>().Value();
    }
    owned_ = std::make_unique<HEVEC::Ciphertext>(isExtended);
    ctxt_ = owned_.get();
  }

  ~CiphertextWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::Ciphertext *Get() { return ctxt_; }

private:
  void SetIsNTT(const Napi::CallbackInfo &info) {
    if (info.Length() < 1 || !info[0].IsBoolean()) {
      Napi::TypeError::New(info.Env(), "Expected boolean")
          .ThrowAsJavaScriptException();
      return;
    }
    ctxt_->setIsNTT(info[0].As<Napi::Boolean>().Value());
  }

  Napi::Value GetDegree(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(), static_cast<double>(ctxt_->getDegree()));
  }

  Napi::Value GetIsExtended(const Napi::CallbackInfo &info) {
    return Napi::Boolean::New(info.Env(), ctxt_->getIsExtended());
  }

  Napi::Value GetIsNTT(const Napi::CallbackInfo &info) {
    return Napi::Boolean::New(info.Env(), ctxt_->getIsNTT());
  }

  Napi::Value GetA(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &ctxt_->getA(), false,
                                       info.This().As<Napi::Object>());
  }

  Napi::Value GetB(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &ctxt_->getB(), false,
                                       info.This().As<Napi::Object>());
  }

  Napi::Value GetC(const Napi::CallbackInfo &info) {
    if (!ctxt_->getIsExtended()) {
      Napi::Error::New(info.Env(), "Ciphertext is not extended")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    return PolynomialWrap::NewExternal(info.Env(), &ctxt_->getC(), false,
                                       info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::Ciphertext> owned_;
  HEVEC::Ciphertext *ctxt_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference CiphertextWrap::constructor;

class MLWECiphertextWrap : public Napi::ObjectWrap<MLWECiphertextWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "MLWECiphertext",
                    {
                        InstanceMethod("getA", &MLWECiphertextWrap::GetA),
                        InstanceMethod("getB", &MLWECiphertextWrap::GetB),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("MLWECiphertext", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::MLWECiphertext *ctxt,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::MLWECiphertext>::New(env, ctxt));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  MLWECiphertextWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<MLWECiphertextWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      ctxt_ = info[0].As<Napi::External<HEVEC::MLWECiphertext>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(),
                           "MLWECiphertext(rank) requires rank argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto rank = RequireUint<HEVEC::u64>(info.Env(), info[0], "rank");
    owned_ = std::make_unique<HEVEC::MLWECiphertext>(rank);
    ctxt_ = owned_.get();
  }

  ~MLWECiphertextWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::MLWECiphertext *Get() { return ctxt_; }

private:
  Napi::Value GetA(const Napi::CallbackInfo &info) {
    auto idx = RequireIndex(info.Env(), info[0], "index");
    return PolynomialWrap::NewExternal(info.Env(), &ctxt_->getA(idx), false,
                                       info.This().As<Napi::Object>());
  }

  Napi::Value GetB(const Napi::CallbackInfo &info) {
    return PolynomialWrap::NewExternal(info.Env(), &ctxt_->getB(), false,
                                       info.This().As<Napi::Object>());
  }

  std::unique_ptr<HEVEC::MLWECiphertext> owned_;
  HEVEC::MLWECiphertext *ctxt_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference MLWECiphertextWrap::constructor;

class CachedQueryWrap : public Napi::ObjectWrap<CachedQueryWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "CachedQuery", {InstanceMethod("size", &CachedQueryWrap::Size)});
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("CachedQuery", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::CachedQuery *cache,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::CachedQuery>::New(env, cache));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  CachedQueryWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<CachedQueryWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      cache_ = info[0].As<Napi::External<HEVEC::CachedQuery>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(),
                           "CachedQuery(rank) requires rank argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto rank = RequireUint<HEVEC::u64>(info.Env(), info[0], "rank");
    owned_ = std::make_unique<HEVEC::CachedQuery>(rank);
    cache_ = owned_.get();
  }

  ~CachedQueryWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::CachedQuery *Get() { return cache_; }

private:
  Napi::Value Size(const Napi::CallbackInfo &info) {
    return Napi::Number::New(
        info.Env(), static_cast<double>(cache_->getCtxts().size()));
  }

  std::unique_ptr<HEVEC::CachedQuery> owned_;
  HEVEC::CachedQuery *cache_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference CachedQueryWrap::constructor;

class CachedKeysWrap : public Napi::ObjectWrap<CachedKeysWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "CachedKeys", {InstanceMethod("size", &CachedKeysWrap::Size)});
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("CachedKeys", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::CachedKeys *cache,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::CachedKeys>::New(env, cache));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  CachedKeysWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<CachedKeysWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      cache_ = info[0].As<Napi::External<HEVEC::CachedKeys>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(),
                           "CachedKeys(rank) requires rank argument")
          .ThrowAsJavaScriptException();
      return;
    }
    auto rank = RequireUint<HEVEC::u64>(info.Env(), info[0], "rank");
    owned_ = std::make_unique<HEVEC::CachedKeys>(rank);
    cache_ = owned_.get();
  }

  ~CachedKeysWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::CachedKeys *Get() { return cache_; }

private:
  Napi::Value Size(const Napi::CallbackInfo &info) {
    return Napi::Number::New(
        info.Env(), static_cast<double>(cache_->getCtxts().size()));
  }

  std::unique_ptr<HEVEC::CachedKeys> owned_;
  HEVEC::CachedKeys *cache_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference CachedKeysWrap::constructor;

class TopKWrap : public Napi::ObjectWrap<TopKWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "TopK",
                    {InstanceMethod("get", &TopKWrap::GetItem),
                     InstanceMethod("set", &TopKWrap::SetItem),
                     InstanceMethod("length", &TopKWrap::Length)});
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("TopK", func);
  }

  static Napi::Object NewExternal(Napi::Env env, HEVEC::TopK *topK,
                                  Napi::Object parent = Napi::Object()) {
    std::vector<napi_value> args;
    args.push_back(Napi::External<HEVEC::TopK>::New(env, topK));
    if (!parent.IsEmpty()) {
      args.push_back(parent);
    }
    return constructor.New(args);
  }

  TopKWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<TopKWrap>(info) {
    if (info.Length() >= 1 && info[0].IsExternal()) {
      topK_ = info[0].As<Napi::External<HEVEC::TopK>>().Data();
      if (info.Length() >= 2 && info[1].IsObject()) {
        parentRef_ = Napi::Persistent(info[1].As<Napi::Object>());
        parentRef_.Ref();
      }
      return;
    }
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(), "TopK(k) requires k argument")
          .ThrowAsJavaScriptException();
      return;
    }
    size_t k = RequireIndex(info.Env(), info[0], "k");
    owned_ = std::make_unique<HEVEC::TopK>(k);
    topK_ = owned_.get();
  }

  ~TopKWrap() override {
    if (!parentRef_.IsEmpty()) {
      parentRef_.Unref();
    }
  }

  HEVEC::TopK *Get() { return topK_; }

private:
  Napi::Value GetItem(const Napi::CallbackInfo &info) {
    size_t idx = RequireIndex(info.Env(), info[0], "index");
    if (idx >= topK_->size()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    return Napi::Number::New(info.Env(), (*topK_)[idx]);
  }

  void SetItem(const Napi::CallbackInfo &info) {
    size_t idx = RequireIndex(info.Env(), info[0], "index");
    int value = static_cast<int>(RequireNumber(info.Env(), info[1], "value"));
    if (idx >= topK_->size()) {
      Napi::RangeError::New(info.Env(), "Index out of range")
          .ThrowAsJavaScriptException();
      return;
    }
    (*topK_)[idx] = value;
  }

  Napi::Value Length(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(), static_cast<double>(topK_->size()));
  }

  std::unique_ptr<HEVEC::TopK> owned_;
  HEVEC::TopK *topK_{nullptr};
  Napi::ObjectReference parentRef_;
};

Napi::FunctionReference TopKWrap::constructor;

class ClientWrap : public Napi::ObjectWrap<ClientWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "Client",
        {
            InstanceMethod("genSecKey", &ClientWrap::GenSecKey),
            InstanceMethod("genRelinKey", &ClientWrap::GenRelinKey),
            InstanceMethod("genAutedModPackKeys",
                           &ClientWrap::GenAutedModPackKeys),
            InstanceMethod("genInvAutedModPackKeys",
                           &ClientWrap::GenInvAutedModPackKeys),
            InstanceMethod("encryptQuery", &ClientWrap::EncryptQuery),
            InstanceMethod("encryptKey", &ClientWrap::EncryptKey),
            InstanceMethod("encode", &ClientWrap::Encode),
            InstanceMethod("decode", &ClientWrap::Decode),
            InstanceMethod("encryptPolynomial", &ClientWrap::EncryptPolynomial),
            InstanceMethod("encryptMessage", &ClientWrap::EncryptMessage),
            InstanceMethod("decrypt", &ClientWrap::Decrypt),
            InstanceMethod("decryptScore", &ClientWrap::DecryptScore),
            InstanceMethod("topKScore", &ClientWrap::TopKScore),
            InstanceMethod("getRank", &ClientWrap::GetRank),
            InstanceMethod("getInvRank", &ClientWrap::GetInvRank),
        });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("Client", func);
  }

  ClientWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<ClientWrap>(info) {
    if (info.Length() < 1) {
      Napi::TypeError::New(info.Env(), "Client(logRank) requires logRank")
          .ThrowAsJavaScriptException();
      return;
    }
    auto logRank = RequireUint<HEVEC::u64>(info.Env(), info[0], "logRank");
    client_ = std::make_unique<HEVEC::Client>(logRank);
  }

  HEVEC::Client *Get() { return client_.get(); }

private:
  void GenSecKey(const Napi::CallbackInfo &info) {
    auto *secKey = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    client_->genSecKey(*secKey);
  }

  void GenRelinKey(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<SwitchingKeyWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    client_->genRelinKey(*res, *sec);
  }

  void GenAutedModPackKeys(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<AutedModPackKeysWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    client_->genAutedModPackKeys(*res, *sec);
  }

  void GenInvAutedModPackKeys(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<AutedModPackMLWEKeysWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    client_->genInvAutedModPackKeys(*res, *sec);
  }

  void EncryptQuery(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<MLWECiphertextWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *msg = Napi::ObjectWrap<MessageWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[3], "scale");
    client_->encryptQuery(*res, *msg, *sec, scale);
  }

  void EncryptKey(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<MLWECiphertextWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *msg = Napi::ObjectWrap<MessageWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[3], "scale");
    client_->encryptKey(*res, *msg, *sec, scale);
  }

  void Encode(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<PolynomialWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *msg = Napi::ObjectWrap<MessageWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[2], "scale");
    client_->encode(*res, *msg, scale);
  }

  void Decode(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<MessageWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *poly = Napi::ObjectWrap<PolynomialWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[2], "scale");
    client_->decode(*res, *poly, scale);
  }

  void EncryptPolynomial(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<CiphertextWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *ptxt = Napi::ObjectWrap<PolynomialWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    client_->encrypt(*res, *ptxt, *sec);
  }

  void EncryptMessage(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<CiphertextWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *msg = Napi::ObjectWrap<MessageWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[3], "scale");
    client_->encrypt(*res, *msg, *sec, scale);
  }

  void Decrypt(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<MessageWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *ctxt = Napi::ObjectWrap<CiphertextWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[3], "scale");
    client_->decrypt(*res, *ctxt, *sec, scale);
  }

  void DecryptScore(const Napi::CallbackInfo &info) {
    if (!info[0].IsArray() || !info[1].IsArray()) {
      Napi::TypeError::New(info.Env(),
                           "Expected arrays of Messages and Ciphertexts")
          .ThrowAsJavaScriptException();
      return;
    }
    Napi::Array msgArr = info[0].As<Napi::Array>();
    Napi::Array scoreArr = info[1].As<Napi::Array>();
    std::vector<HEVEC::Message> msgs;
    msgs.reserve(msgArr.Length());
    for (size_t i = 0; i < msgArr.Length(); ++i) {
      auto *wrap = Napi::ObjectWrap<MessageWrap>::Unwrap(
          msgArr.Get(i).As<Napi::Object>());
      msgs.emplace_back(*wrap->Get());
    }
    std::vector<HEVEC::Ciphertext> ctxts;
    ctxts.reserve(scoreArr.Length());
    for (size_t i = 0; i < scoreArr.Length(); ++i) {
      auto *wrap = Napi::ObjectWrap<CiphertextWrap>::Unwrap(
          scoreArr.Get(i).As<Napi::Object>());
      ctxts.emplace_back(*wrap->Get());
    }
    auto *sec = Napi::ObjectWrap<SecretKeyWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    double scale = RequireNumber(info.Env(), info[3], "scale");
    client_->decryptScore(msgs, ctxts, *sec, scale);
    for (size_t i = 0; i < msgArr.Length(); ++i) {
      auto *wrap =
          Napi::ObjectWrap<MessageWrap>::Unwrap(msgArr.Get(i).As<Napi::Object>());
      auto src = msgs[i];
      auto dst = wrap->Get();
      for (HEVEC::u64 j = 0; j < src.getDegree(); ++j) {
        (*dst)[j] = src[j];
      }
    }
  }

  void TopKScore(const Napi::CallbackInfo &info) {
    if (!info[1].IsArray()) {
      Napi::TypeError::New(info.Env(), "Expected array of Message instances")
          .ThrowAsJavaScriptException();
      return;
    }
    auto *topK = Napi::ObjectWrap<TopKWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    Napi::Array arr = info[1].As<Napi::Array>();
    std::vector<HEVEC::Message> msgs;
    msgs.reserve(arr.Length());
    for (size_t i = 0; i < arr.Length(); ++i) {
      auto *wrap =
          Napi::ObjectWrap<MessageWrap>::Unwrap(arr.Get(i).As<Napi::Object>());
      msgs.emplace_back(*wrap->Get());
    }
    client_->topKScore(*topK, msgs);
  }

  Napi::Value GetRank(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(),
                             static_cast<double>(client_->getRank()));
  }

  Napi::Value GetInvRank(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(),
                             static_cast<double>(client_->getInvRank()));
  }

  std::unique_ptr<HEVEC::Client> client_;
};

Napi::FunctionReference ClientWrap::constructor;

class ServerWrap : public Napi::ObjectWrap<ServerWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func =
        DefineClass(env, "Server",
                    {
                        InstanceMethod("cacheQuery", &ServerWrap::CacheQuery),
                        InstanceMethod("cacheKeys", &ServerWrap::CacheKeys),
                        InstanceMethod("innerProduct",
                                       &ServerWrap::InnerProduct),
                    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("Server", func);
  }

  ServerWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<ServerWrap>(info) {
    if (info.Length() < 4) {
      Napi::TypeError::New(info.Env(),
                           "Server(logRank, relinKey, autedKeys, mlweKeys)")
          .ThrowAsJavaScriptException();
      return;
    }
    auto logRank = RequireUint<HEVEC::u64>(info.Env(), info[0], "logRank");
    auto *relin =
        Napi::ObjectWrap<SwitchingKeyWrap>::Unwrap(info[1].As<Napi::Object>())
            ->Get();
    auto *auted =
        Napi::ObjectWrap<AutedModPackKeysWrap>::Unwrap(info[2].As<Napi::Object>())
            ->Get();
    auto *mlwe = Napi::ObjectWrap<AutedModPackMLWEKeysWrap>::Unwrap(
        info[3].As<Napi::Object>())
                     ->Get();
    server_ = std::make_unique<HEVEC::Server>(logRank, *relin, *auted, *mlwe);
  }

private:
  void CacheQuery(const Napi::CallbackInfo &info) {
    auto *cache = Napi::ObjectWrap<CachedQueryWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *query = Napi::ObjectWrap<MLWECiphertextWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    server_->cacheQuery(*cache, *query);
  }

  void CacheKeys(const Napi::CallbackInfo &info) {
    auto *cache = Napi::ObjectWrap<CachedKeysWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    if (!info[1].IsArray()) {
      Napi::TypeError::New(info.Env(), "Expected array of MLWECiphertext")
          .ThrowAsJavaScriptException();
      return;
    }
    Napi::Array arr = info[1].As<Napi::Array>();
    std::vector<HEVEC::MLWECiphertext> keys;
    keys.reserve(arr.Length());
    for (size_t i = 0; i < arr.Length(); ++i) {
      auto *wrap = Napi::ObjectWrap<MLWECiphertextWrap>::Unwrap(
          arr.Get(i).As<Napi::Object>());
      keys.emplace_back(*wrap->Get());
    }
    server_->cacheKeys(*cache, keys);
  }

  void InnerProduct(const Napi::CallbackInfo &info) {
    auto *res = Napi::ObjectWrap<CiphertextWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    auto *query = Napi::ObjectWrap<CachedQueryWrap>::Unwrap(
        info[1].As<Napi::Object>())->Get();
    auto *keys = Napi::ObjectWrap<CachedKeysWrap>::Unwrap(
        info[2].As<Napi::Object>())->Get();
    server_->innerProduct(*res, *query, *keys);
  }

  std::unique_ptr<HEVEC::Server> server_;
};

Napi::FunctionReference ServerWrap::constructor;

class HEVECClientWrap : public Napi::ObjectWrap<HEVECClientWrap> {
public:
  static Napi::FunctionReference constructor;

  static void Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "HEVECClient",
        {
            InstanceMethod("setupCollection",
                           &HEVECClientWrap::SetupCollection),
            InstanceMethod("dropCollection", &HEVECClientWrap::DropCollection),
            InstanceMethod("terminate", &HEVECClientWrap::Terminate),
            InstanceMethod("insert", &HEVECClientWrap::Insert),
            InstanceMethod("query", &HEVECClientWrap::Query),
            InstanceMethod("queryAndTopK", &HEVECClientWrap::QueryAndTopK),
            InstanceMethod("queryAndTopKWithScores",
                           &HEVECClientWrap::QueryAndTopKWithScores),
            InstanceMethod("retrieve", &HEVECClientWrap::Retrieve),
            InstanceMethod("retrievePIR", &HEVECClientWrap::RetrievePIR),
        });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("HEVECClient", func);
  }

  static void InitStatic(Napi::Env env, Napi::Object exports) {
    exports.Set("getTopKIndices",
                Napi::Function::New(env, &HEVECClientWrap::GetTopKIndices));
  }

  HEVECClientWrap(const Napi::CallbackInfo &info)
      : Napi::ObjectWrap<HEVECClientWrap>(info) {
    if (info.Length() < 2) {
      Napi::TypeError::New(info.Env(),
                           "HEVECClient(host, port) requires two arguments")
          .ThrowAsJavaScriptException();
      return;
    }
    if (!info[0].IsString() || !info[1].IsString()) {
      Napi::TypeError::New(info.Env(), "Host and port must be strings")
          .ThrowAsJavaScriptException();
      return;
    }
    client_ = std::make_unique<HEVEC::HEVECClient>(
        info[0].As<Napi::String>().Utf8Value(),
        info[1].As<Napi::String>().Utf8Value());
  }

private:
  Napi::Value SetupCollection(const Napi::CallbackInfo &info) {
    if (info.Length() < 4) {
      Napi::TypeError::New(
          info.Env(),
          "setupCollection(collectionName, dimension, metricType, isQueryEncrypt)")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    std::string name = info[0].As<Napi::String>().Utf8Value();
    auto dim = RequireUint<HEVEC::u64>(info.Env(), info[1], "dimension");
    std::string metric = info[2].As<Napi::String>().Utf8Value();
    bool isQueryEncrypt =
        info.Length() >= 4 ? info[3].As<Napi::Boolean>().Value() : true;
    auto res = client_->setupCollection(name, dim, metric, isQueryEncrypt);
    return Napi::BigInt::New(info.Env(), res);
  }

  void DropCollection(const Napi::CallbackInfo &info) {
    std::string name = info[0].As<Napi::String>().Utf8Value();
    client_->dropCollection(name);
  }

  void Terminate(const Napi::CallbackInfo &info) { client_->terminate(); }

  void Insert(const Napi::CallbackInfo &info) {
    if (info.Length() < 3) {
      Napi::TypeError::New(info.Env(),
                           "insert(collectionName, db, payloads)")
          .ThrowAsJavaScriptException();
      return;
    }
    std::string name = info[0].As<Napi::String>().Utf8Value();
    if (!info[2].IsArray()) {
      Napi::TypeError::New(info.Env(), "payloads must be array of strings")
          .ThrowAsJavaScriptException();
      return;
    }
    auto matrix = RequireFloatMatrix(info.Env(), info[1], "db");
    Napi::Array payloads = info[2].As<Napi::Array>();
    std::vector<std::string> payloadVec(payloads.Length());
    for (size_t i = 0; i < payloads.Length(); ++i) {
      payloadVec[i] = payloads.Get(i).As<Napi::String>().Utf8Value();
    }
    client_->insert(name, matrix, payloadVec);
  }

  Napi::Value Query(const Napi::CallbackInfo &info) {
    if (info.Length() < 2) {
      Napi::TypeError::New(info.Env(), "query(collectionName, queryVec)")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    std::string name = info[0].As<Napi::String>().Utf8Value();
    auto vec = RequireFloatVector(info.Env(), info[1], "query");
    auto result = client_->query(name, vec);
    Napi::Array arr = Napi::Array::New(info.Env(), result.size());
    for (size_t i = 0; i < result.size(); ++i) {
      arr.Set(i, Napi::Number::New(info.Env(), result[i]));
    }
    return arr;
  }

  void QueryAndTopK(const Napi::CallbackInfo &info) {
    if (info.Length() < 3) {
      Napi::TypeError::New(info.Env(),
                           "queryAndTopK(resTopK, collectionName, queryVec)")
          .ThrowAsJavaScriptException();
      return;
    }
    auto *topK = Napi::ObjectWrap<TopKWrap>::Unwrap(
        info[0].As<Napi::Object>())->Get();
    std::string name = info[1].As<Napi::String>().Utf8Value();
    auto vec = RequireFloatVector(info.Env(), info[2], "query");
    client_->queryAndTopK(*topK, name, vec);
  }

  Napi::Value QueryAndTopKWithScores(const Napi::CallbackInfo &info) {
    if (info.Length() < 3) {
      Napi::TypeError::New(
          info.Env(),
          "queryAndTopKWithScores(collectionName, queryVec, k)")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    std::string name = info[0].As<Napi::String>().Utf8Value();
    auto vec = RequireFloatVector(info.Env(), info[1], "query");
    auto k = RequireUint<HEVEC::u64>(info.Env(), info[2], "k");
    std::vector<std::pair<HEVEC::u64, float>> results;
    client_->queryAndTopKWithScores(results, name, vec, k);
    Napi::Array arr = Napi::Array::New(info.Env(), results.size());
    for (size_t i = 0; i < results.size(); ++i) {
      Napi::Array pair = Napi::Array::New(info.Env(), 2);
      pair.Set(static_cast<uint32_t>(0),
               Napi::BigInt::New(info.Env(), results[i].first));
      pair.Set(static_cast<uint32_t>(1),
               Napi::Number::New(info.Env(), results[i].second));
      arr.Set(i, pair);
    }
    return arr;
  }

  Napi::Value Retrieve(const Napi::CallbackInfo &info) {
    std::string name = info[0].As<Napi::String>().Utf8Value();
    auto index = RequireUint<HEVEC::u64>(info.Env(), info[1], "index");
    return Napi::String::New(info.Env(), client_->retrieve(name, index));
  }

  Napi::Value RetrievePIR(const Napi::CallbackInfo &info) {
    std::string name = info[0].As<Napi::String>().Utf8Value();
    auto index = RequireUint<HEVEC::u64>(info.Env(), info[1], "index");
    return Napi::String::New(info.Env(), client_->retrievePIR(name, index));
  }

  static Napi::Value GetTopKIndices(const Napi::CallbackInfo &info) {
    if (info.Length() < 2) {
      Napi::TypeError::New(info.Env(), "getTopKIndices(scores, k)")
          .ThrowAsJavaScriptException();
      return info.Env().Undefined();
    }
    auto scores = RequireFloatVector(info.Env(), info[0], "scores");
    auto k = RequireUint<HEVEC::u64>(info.Env(), info[1], "k");
    auto result = HEVEC::HEVECClient::getTopKIndices(scores, k);
    Napi::Array arr = Napi::Array::New(info.Env(), result.size());
    for (size_t i = 0; i < result.size(); ++i) {
      arr.Set(i, Napi::BigInt::New(info.Env(), result[i]));
    }
    return arr;
  }

  std::unique_ptr<HEVEC::HEVECClient> client_;
};

Napi::FunctionReference HEVECClientWrap::constructor;

void ExportMetricType(Napi::Env env, Napi::Object exports) {
  Napi::Object metric = Napi::Object::New(env);
  metric.Set("IP", Napi::Number::New(env, static_cast<int>(HEVEC::MetricType::IP)));
  metric.Set("L2", Napi::Number::New(env, static_cast<int>(HEVEC::MetricType::L2)));
  metric.Set("COSINE",
             Napi::Number::New(env, static_cast<int>(HEVEC::MetricType::COSINE)));
  exports.Set("MetricType", metric);
}

} // namespace

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
  MessageWrap::Init(env, exports);
  PolynomialWrap::Init(env, exports);
  SecretKeyWrap::Init(env, exports);
  SwitchingKeyWrap::Init(env, exports);
  MLWESwitchingKeyWrap::Init(env, exports);
  AutedModPackKeysWrap::Init(env, exports);
  AutedModPackMLWEKeysWrap::Init(env, exports);
  CiphertextWrap::Init(env, exports);
  MLWECiphertextWrap::Init(env, exports);
  CachedQueryWrap::Init(env, exports);
  CachedKeysWrap::Init(env, exports);
  TopKWrap::Init(env, exports);
  ClientWrap::Init(env, exports);
  ServerWrap::Init(env, exports);
  HEVECClientWrap::Init(env, exports);
  HEVECClientWrap::InitStatic(env, exports);
  ExportMetricType(env, exports);
  return exports;
}

NODE_API_MODULE(hevec_node, InitAll)
