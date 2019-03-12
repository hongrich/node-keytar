#include "nan.h"
#include "async.h"
#include "keytar.h"

using keytar::KEYTAR_OP_RESULT;

namespace {

NAN_METHOD(SetPassword) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());
  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());
  Nan::Utf8String passwordNan(info[2]);
  std::string password(*passwordNan, passwordNan.length());

  SetPasswordWorker* worker = new SetPasswordWorker(
    service,
    username,
    password,
    new Nan::Callback(info[3].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(GetPassword) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());
  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  GetPasswordWorker* worker = new GetPasswordWorker(
    service,
    username,
    new Nan::Callback(info[2].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(DeletePassword) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());
  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  DeletePasswordWorker* worker = new DeletePasswordWorker(
    service,
    username,
    new Nan::Callback(info[2].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(FindPassword) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  FindPasswordWorker* worker = new FindPasswordWorker(
    service,
    new Nan::Callback(info[1].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(FindCredentials) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  FindCredentialsWorker* worker = new FindCredentialsWorker(
    service,
    new Nan::Callback(info[1].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(SetPasswordSync) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());
  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());
  Nan::Utf8String passwordNan(info[2]);
  std::string password(*passwordNan, passwordNan.length());

  std::string error;
  KEYTAR_OP_RESULT result = keytar::SetPassword(service,
                                                username,
                                                password,
                                                &error);
  if (result == keytar::FAIL_ERROR) {
    // FIXME: throw error on fatal failure
    // Nan::ThrowError(error.c_str());
  }
}

NAN_METHOD(GetPasswordSync) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());
  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  std::string password;
  std::string error;
  KEYTAR_OP_RESULT result = keytar::GetPassword(service,
                                                username,
                                                &password,
                                                &error);
  if (result == keytar::FAIL_ERROR) {
    // FIXME: throw error on fatal failure and don't return null
    // Nan::ThrowError(error.c_str());
    info.GetReturnValue().Set(Nan::Null());
  } else if (result == keytar::FAIL_NONFATAL) {
    info.GetReturnValue().Set(Nan::Null());
  } else {
    v8::Local<v8::Value> val =
      Nan::New<v8::String>(password.data(),
                           password.length()).ToLocalChecked();
    info.GetReturnValue().Set(val);
  }
}

NAN_METHOD(DeletePasswordSync) {
  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());
  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  std::string error;
  KEYTAR_OP_RESULT result = keytar::DeletePassword(service, username, &error);
  if (result == keytar::FAIL_ERROR) {
    // FIXME: throw error on fatal failure and don't return false
    // Nan::ThrowError(error.c_str());
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  } else if (result == keytar::FAIL_NONFATAL) {
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  } else {
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));
  }
}

void Init(v8::Local<v8::Object> exports) {
  Nan::SetMethod(exports, "getPassword", GetPassword);
  Nan::SetMethod(exports, "setPassword", SetPassword);
  Nan::SetMethod(exports, "deletePassword", DeletePassword);
  Nan::SetMethod(exports, "findPassword", FindPassword);
  Nan::SetMethod(exports, "findCredentials", FindCredentials);
  Nan::SetMethod(exports, "getPasswordSync", GetPasswordSync);
  Nan::SetMethod(exports, "setPasswordSync", SetPasswordSync);
  Nan::SetMethod(exports, "deletePasswordSync", DeletePasswordSync);
}

}  // namespace

NODE_MODULE(keytar, Init)
