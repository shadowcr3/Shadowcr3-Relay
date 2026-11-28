#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "relay_crypto_soft.h"

#if !defined(RELAY_CRYPTO_PORTABLE) && defined(__has_include)
#if __has_include("mbedtls/aes.h") && __has_include("mbedtls/md.h")
#define RELAY_HAVE_MBEDTLS 1
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#endif
#endif

namespace relay {
namespace crypto {

inline void secureZero(void *p, size_t n) {
  volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
  while (n--) *v++ = 0;
}

inline bool ctEqual(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

#ifdef RELAY_HAVE_MBEDTLS
namespace mbed {

inline bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info != nullptr && mbedtls_md_hmac(info, key, keyLen, data, len, out) == 0;
}

inline bool aes128Ctr(const uint8_t key[16], const uint8_t counterBlock[16], const uint8_t *in, uint8_t *out,
                      size_t len) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  bool ok = mbedtls_aes_setkey_enc(&ctx, key, 128) == 0;
  if (ok) {
    uint8_t counter[16];
    uint8_t stream[16];
    size_t offset = 0;
    memcpy(counter, counterBlock, 16);
    ok = mbedtls_aes_crypt_ctr(&ctx, len, &offset, counter, stream, in, out) == 0;
    secureZero(counter, sizeof counter);
    secureZero(stream, sizeof stream);
  }
  mbedtls_aes_free(&ctx);
  return ok;
}

}  

constexpr const char *kBackendName = "mbedtls";
inline bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]) {
  return mbed::hmacSha256(key, keyLen, data, len, out);
}
inline bool aes128Ctr(const uint8_t key[16], const uint8_t counterBlock[16], const uint8_t *in, uint8_t *out,
                      size_t len) {
  return mbed::aes128Ctr(key, counterBlock, in, out, len);
}
#else
constexpr const char *kBackendName = "portable";
inline bool hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]) {
  return soft::hmacSha256(key, keyLen, data, len, out);
}
inline bool aes128Ctr(const uint8_t key[16], const uint8_t counterBlock[16], const uint8_t *in, uint8_t *out,
                      size_t len) {
  return soft::aes128Ctr(key, counterBlock, in, out, len);
}
#endif

}  
} 
