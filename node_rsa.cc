#include "node_rsa.h"

#include <v8.h>

#include <node.h>
#include <node_buffer.h>

#include <string.h>
#include <stdlib.h>

#include <errno.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
# define OPENSSL_CONST const
#else
# define OPENSSL_CONST
#endif

namespace node {

using namespace v8;

// hex_encode, hex_decode, base64, unbase64 nicked from node_crypto.cc

void hex_encode(unsigned char *md_value, int md_len, char** md_hexdigest,
                int* md_hex_len) {
  *md_hex_len = (2*(md_len));
  *md_hexdigest = (char *) malloc(*md_hex_len + 1);
  for (int i = 0; i < md_len; i++) {
    sprintf((char *)(*md_hexdigest + (i*2)), "%02x",  md_value[i]);
  }
}

#define hex2i(c) ((c) <= '9' ? ((c) - '0') : (c) <= 'Z' ? ((c) - 'A' + 10) \
                 : ((c) - 'a' + 10))
void hex_decode(unsigned char *input, int length, char** buf64, 
                int* buf64_len) {
  *buf64_len = (length/2);
  *buf64 = (char*) malloc(length/2 + 1);
  char *b = *buf64;
  for(int i = 0; i < length-1; i+=2) {
    b[i/2]  = (hex2i(input[i])<<4) | (hex2i(input[i+1]));
  }
}

void base64(unsigned char *input, int length, char** buf64, int* buf64_len)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64, input, length);
  (void)BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  *buf64_len = bptr->length;
  *buf64 = (char *)malloc(*buf64_len+1);
  memcpy(*buf64, bptr->data, bptr->length);
  char* b = *buf64;
  b[bptr->length] = 0;

  BIO_free_all(b64);

}

void unbase64(unsigned char *input, int length, char** buffer, int* buffer_len)
{
  BIO *b64, *bmem;
  *buffer = (char *)malloc(length);
  memset(*buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  *buffer_len = BIO_read(bmem, *buffer, length);
  BIO_free_all(bmem);
}



void RsaKeypair::Initialize(Handle<Object> target) {
  HandleScope scope;

  Local<FunctionTemplate> t = FunctionTemplate::New(RsaKeypair::New);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("RsaKeypair"));

  NODE_SET_PROTOTYPE_METHOD(t, "setPublicKey",
                            RsaKeypair::SetPublicKey);
  NODE_SET_PROTOTYPE_METHOD(t, "setPrivateKey",
                            RsaKeypair::SetPrivateKey);
  NODE_SET_PROTOTYPE_METHOD(t, "encrypt",
                            RsaKeypair::Encrypt);
  NODE_SET_PROTOTYPE_METHOD(t, "decrypt",
                            RsaKeypair::Decrypt);
  NODE_SET_PROTOTYPE_METHOD(t, "getModulus",
                            RsaKeypair::GetModulus);
  NODE_SET_PROTOTYPE_METHOD(t, "getExponent",
                            RsaKeypair::GetExponent);

  target->Set(String::NewSymbol("RsaKeypair"), t->GetFunction());
}

Handle<Value> RsaKeypair::New(const Arguments& args) {
  HandleScope scope;
  RsaKeypair *p = new RsaKeypair();
  p->Wrap(args.Holder());
  p->privateKey = NULL;
  p->publicKey = NULL;
  return args.This();
}

Handle<Value> RsaKeypair::SetPublicKey(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (args.Length() != 1 ||
      !args[0]->IsString()) {
    return ThrowException(Exception::TypeError(
          String::New("Bad parameter")));
  }
  String::Utf8Value pubKey(args[0]->ToString());

  BIO *bp = NULL;
  RSA *key = NULL;

  bp = BIO_new(BIO_s_mem());
  if (!BIO_write(bp, *pubKey, strlen(*pubKey)))
    return False();

  key = PEM_read_bio_RSA_PUBKEY(bp, NULL, NULL, NULL);
  if (key == NULL)
    return False();

  kp->publicKey = key;
  BIO_free(bp);

  return True();
}

Handle<Value> RsaKeypair::SetPrivateKey(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (args.Length() == 2 &&
      (!args[0]->IsString() || !args[1]->IsString())) {
    return ThrowException(Exception::TypeError(
          String::New("Bad parameter")));
  }
  if (args.Length() == 1 &&
      (!args[0]->IsString())) {
    return ThrowException(Exception::TypeError(
          String::New("Bad parameter")));
  }

  BIO *bp = NULL;
  String::Utf8Value privKey(args[0]->ToString());

  bp = BIO_new(BIO_s_mem());
  if (!BIO_write(bp, *privKey, strlen(*privKey)))
    return False();

  RSA *key;
  if (args.Length() == 2) {
    String::Utf8Value passphrase(args[1]->ToString());
    key = PEM_read_bio_RSAPrivateKey(bp, NULL, 0, *passphrase);
  }
  else {
    key = PEM_read_bio_RSAPrivateKey(bp, NULL, 0, NULL);
  }
  if (key == NULL) {
    return False();
  }

  kp->privateKey = key;
  BIO_free(bp);

  return True();
}

Handle<Value> RsaKeypair::Encrypt(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (kp->publicKey == NULL) {
    Local<Value> exception = Exception::Error(String::New("Can't encrypt, no public key"));
    return ThrowException(exception);
  }

  enum encoding enc = ParseEncoding(args[1]);
  ssize_t len = DecodeBytes(args[0], enc);
  
  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  // check per RSA_public_encrypt(3) when using OAEP
  if (len >= RSA_size(kp->publicKey) - 41) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument (too long for key size)"));
    return ThrowException(exception);
  }

  unsigned char* buf = new unsigned char[len];
  ssize_t written = DecodeWrite((char *)buf, len, args[0], enc);
  assert(written == len);  

  int out_len = RSA_size(kp->publicKey);
  unsigned char *out = (unsigned char*)malloc(out_len);

  int r = RSA_public_encrypt(len, buf, out, kp->publicKey, RSA_PKCS1_OAEP_PADDING);

  if (r < 0) {
    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<String> full_err = String::Concat(String::New("RSA encrypt: "), String::New(err));
    Local<Value> exception = Exception::Error(full_err);
    return ThrowException(exception);
  }

  Local<Value> outString;
  if (out_len == 0) {
    outString = String::New("");
  }
  else {
    if (args.Length() <= 2 || !args[2]->IsString()) {
      outString = Encode(out, out_len, BINARY);
    } else {
      char* out_hexdigest;
      int out_hex_len;
      String::Utf8Value encoding(args[2]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
	hex_encode(out, out_len, &out_hexdigest, &out_hex_len);
	outString = Encode(out_hexdigest, out_hex_len, BINARY);
	free(out_hexdigest);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        base64(out, out_len, &out_hexdigest, &out_hex_len);
        outString = Encode(out_hexdigest, out_hex_len, BINARY);
        free(out_hexdigest);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        outString = Encode(out, out_len, BINARY);
      } else {
	outString = String::New("");
	Local<Value> exception = Exception::Error(String::New("RsaKeypair.encrypt encoding "
							      "can be binary, base64 or hex"));
	return ThrowException(exception);
      }
    }
  }
  if (out) free(out);
  return scope.Close(outString);
}

Handle<Value> RsaKeypair::Decrypt(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (kp->privateKey == NULL) {
    Local<Value> exception = Exception::Error(String::New("Can't decrypt, no private key"));
    return ThrowException(exception);
  }

  ssize_t len = DecodeBytes(args[0], BINARY);
  unsigned char* buf = new unsigned char[len];
  (void)DecodeWrite((char *)buf, len, args[0], BINARY);
  unsigned char* ciphertext;
  int ciphertext_len;

  if (args.Length() <= 1 || !args[1]->IsString()) {
      // Binary - do nothing
  } else {
    String::Utf8Value encoding(args[1]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      hex_decode((unsigned char*)buf, len, (char **)&ciphertext, &ciphertext_len);
      free(buf);
      buf = ciphertext;
      len = ciphertext_len;
    } else if (strcasecmp(*encoding, "base64") == 0) {
      unbase64((unsigned char*)buf, len, (char **)&ciphertext, &ciphertext_len);
      free(buf);
      buf = ciphertext;
      len = ciphertext_len;
    } else if (strcasecmp(*encoding, "binary") == 0) {
      // Binary - do nothing
    } else {
      Local<Value> exception = Exception::Error(String::New("RsaKeypair.decrypt encoding "
							    "can be binary, base64 or hex"));
      return ThrowException(exception);
    }
  }

  // XXX is this check unnecessary? is it just len <= keysize?
  // check per RSA_public_encrypt(3) when using OAEP
  //if (len > RSA_size(kp->privateKey) - 41) {
  //  Local<Value> exception = Exception::Error(String::New("Bad argument (too long for key size)"));
  //  return ThrowException(exception);
  //}
  
  int out_len = RSA_size(kp->privateKey);
  unsigned char *out = (unsigned char*)malloc(out_len);
  
  out_len = RSA_private_decrypt(len, buf, out, kp->privateKey, RSA_PKCS1_OAEP_PADDING);

  if (out_len < 0) {
    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<String> full_err = String::Concat(String::New("RSA decrypt: "), String::New(err));
    Local<Value> exception = Exception::Error(full_err);
    return ThrowException(exception);
  }
  
  Local<Value> outString;
  if (out_len == 0) {
    outString = String::New("");
  } else if (args.Length() <= 2 || !args[2]->IsString()) {
    outString = Encode(out, out_len, BINARY);
  } else {
    enum encoding enc = ParseEncoding(args[2]);
    outString = Encode(out, out_len, enc);
  }

  if (out) free(out);
  free(buf);
  return scope.Close(outString);
}

Handle<Value> RsaKeypair::GetBignum(const Arguments& args, WhichComponent which) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());
  RSA *target = (kp->privateKey != NULL) ? kp->privateKey : kp->publicKey;

  if (target == NULL) {
    Local<Value> exception = Exception::Error(String::New("No key set"));
    return ThrowException(exception);
  }

  BIGNUM *number = (which == MODULUS) ? target->n : target->e;
  int out_len = BN_num_bytes(number);
  unsigned char *out = new unsigned char[out_len];

  out_len = BN_bn2bin(number, out); // Return value also indicates error.

  if (out_len < 0) {
    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<String> full_err = String::Concat(String::New("Get: "), String::New(err));
    Local<Value> exception = Exception::Error(full_err);
    return ThrowException(exception);
  }

  Local<Value> outString;
  if (out_len == 0) {
    outString = String::New("");
  } else if (args.Length() <= 0 || !args[0]->IsString()) {
    outString = Encode(out, out_len, BINARY);
  } else {
    char* out_hexdigest;
    int out_hex_len;
    String::Utf8Value encoding(args[0]->ToString());
    if (strcasecmp(*encoding, "hex") == 0) {
      hex_encode(out, out_len, &out_hexdigest, &out_hex_len);
      outString = Encode(out_hexdigest, out_hex_len, BINARY);
      free(out_hexdigest);
    } else if (strcasecmp(*encoding, "base64") == 0) {
      base64(out, out_len, &out_hexdigest, &out_hex_len);
      outString = Encode(out_hexdigest, out_hex_len, BINARY);
      free(out_hexdigest);
    } else if (strcasecmp(*encoding, "binary") == 0) {
      outString = Encode(out, out_len, BINARY);
    } else {
      outString = String::New("");
      Local<Value> exception = Exception::Error(String::New("RsaKeypair.get* encoding "
							    "can be binary, base64 or hex"));
      return ThrowException(exception);
    }
  }

  if (out) free(out);
  return scope.Close(outString);
}

Handle<Value> RsaKeypair::GetModulus(const Arguments& args) {
  return GetBignum(args, MODULUS);
}

Handle<Value> RsaKeypair::GetExponent(const Arguments& args) {
  return GetBignum(args, EXPONENT);
}

extern "C" void
init(Handle<Object> target) {
    RsaKeypair::Initialize(target);
}

}  // namespace node
