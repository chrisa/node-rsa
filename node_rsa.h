#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

namespace node {

enum WhichComponent {
  MODULUS, EXPONENT
};

class RsaKeypair : ObjectWrap {
 public:
  static void Initialize(v8::Handle<v8::Object> target);

 protected:
  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPrivateKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPublicKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> Encrypt(const v8::Arguments& args);
  static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetModulus(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetExponent(const v8::Arguments& args);

  // Helper for GetModulus() and GetExponent().
  static v8::Handle<v8::Value> GetBignum(const v8::Arguments& args, WhichComponent which);

  RsaKeypair() : ObjectWrap() {
  }

  ~RsaKeypair() {
  }

 private:
  RSA *publicKey;
  RSA *privateKey;
};

} // namespace node
