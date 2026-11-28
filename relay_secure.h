#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "relay_config.h"
#include "relay_crypto.h"

namespace relay {

enum class Role : uint8_t { A = 0, B = 1 };
inline Role peerRole(Role r) { return r == Role::A ? Role::B : Role::A; }

struct DirKeys {
  uint8_t enc[16];
  uint8_t mac[32];
};

struct SessionKeys {
  DirKeys tx;              
  DirKeys rx;              
  uint8_t addr[5];         
  uint8_t fingerprint[4]; 
};

namespace detail {

static const char kSalt[] = "Shadowcr3-Relay-v3";

inline bool hkdfExpand1(const uint8_t prk[32], const char *label, uint8_t out[32]) {
  uint8_t msg[48];
  const size_t n = strlen(label);
  if (n > sizeof(msg) - 1) return false;
  memcpy(msg, label, n);
  msg[n] = 0x01;
  return crypto::hmacSha256(prk, 32, msg, n + 1, out);
}

inline bool deriveDir(const uint8_t prk[32], Role sender, DirKeys &d) {
  uint8_t t[32];
  bool ok = hkdfExpand1(prk, sender == Role::A ? "enc A->B" : "enc B->A", t);
  if (ok) memcpy(d.enc, t, 16);
  ok = ok && hkdfExpand1(prk, sender == Role::A ? "mac A->B" : "mac B->A", d.mac);
  crypto::secureZero(t, sizeof t);
  return ok;
}

}  
inline bool deriveSessionKeys(const uint8_t master[KEY_BYTES], Role role, SessionKeys &k) {
  uint8_t prk[32];
  uint8_t t[32];
  bool ok = crypto::hmacSha256(reinterpret_cast<const uint8_t *>(detail::kSalt), strlen(detail::kSalt), master,
                               KEY_BYTES, prk);  // HKDF-Extract
  ok = ok && detail::deriveDir(prk, role, k.tx);
  ok = ok && detail::deriveDir(prk, peerRole(role), k.rx);
  ok = ok && detail::hkdfExpand1(prk, "rf address", t);
  if (ok) {
    memcpy(k.addr, t, sizeof k.addr);
    if (k.addr[0] == 0x00 || k.addr[0] == 0xFF || k.addr[0] == 0x55 || k.addr[0] == 0xAA) k.addr[0] ^= 0x5A;
  }
  ok = ok && detail::hkdfExpand1(prk, "fingerprint", t);
  if (ok) memcpy(k.fingerprint, t, sizeof k.fingerprint);
  crypto::secureZero(prk, sizeof prk);
  crypto::secureZero(t, sizeof t);
  return ok;
}

namespace detail {
inline void counterBlock(const uint8_t *hdr, uint8_t block[16]) {
  memset(block, 0, 16);
  memcpy(block, hdr, SEC_HEADER_BYTES);  
}
}  

class SecureTx {
 public:
  void init(const DirKeys &keys, uint16_t epoch) {
    keys_ = keys;
    epoch_ = epoch;
    ctr_ = 0;
  }

  bool seal(const uint8_t *plain, uint8_t *pkt) {
    if (ctr_ > COUNTER_MAX) return false;
    pkt[0] = static_cast<uint8_t>(epoch_ >> 8);
    pkt[1] = static_cast<uint8_t>(epoch_);
    pkt[2] = static_cast<uint8_t>(ctr_ >> 16);
    pkt[3] = static_cast<uint8_t>(ctr_ >> 8);
    pkt[4] = static_cast<uint8_t>(ctr_);
    uint8_t block[16];
    detail::counterBlock(pkt, block);
    uint8_t mac[32];
    const bool ok = crypto::aes128Ctr(keys_.enc, block, plain, pkt + SEC_HEADER_BYTES, PLAIN_BYTES) &&
                    crypto::hmacSha256(keys_.mac, sizeof keys_.mac, pkt, SEC_HEADER_BYTES + PLAIN_BYTES, mac);
    if (!ok) return false;
    memcpy(pkt + SEC_HEADER_BYTES + PLAIN_BYTES, mac, TAG_BYTES);
    ++ctr_;
    return true;
  }

  uint32_t counter() const { return ctr_; }
  bool exhausted() const { return ctr_ > COUNTER_MAX; }

 private:
  DirKeys keys_;
  uint16_t epoch_ = 0;
  uint32_t ctr_ = 0;
};

class SecureRx {
 public:
  enum class Result : uint8_t { Ok, BadTag, Replay };

  uint32_t authFail = 0;  
  uint32_t replays = 0;   
  uint32_t accepted = 0;

  void init(const DirKeys &keys, uint16_t minEpoch) {
    keys_ = keys;
    minEpoch_ = minEpoch;
    peerEpoch_ = minEpoch;
    have_ = false;
    last_ = 0;
    authFail = replays = accepted = 0;
  }

  Result open(const uint8_t *pkt, uint8_t *plain, uint64_t &ctr40) {
    const uint16_t epoch = static_cast<uint16_t>((pkt[0] << 8) | pkt[1]);
    const uint32_t ctr = (static_cast<uint32_t>(pkt[2]) << 16) | (static_cast<uint32_t>(pkt[3]) << 8) | pkt[4];
    const uint64_t c40 = (static_cast<uint64_t>(epoch) << 24) | ctr;
    if (epoch < minEpoch_ || (have_ && c40 <= last_)) {
      ++replays;
      return Result::Replay;
    }
    uint8_t mac[32];
    if (!crypto::hmacSha256(keys_.mac, sizeof keys_.mac, pkt, SEC_HEADER_BYTES + PLAIN_BYTES, mac) ||
        !crypto::ctEqual(mac, pkt + SEC_HEADER_BYTES + PLAIN_BYTES, TAG_BYTES)) {
      ++authFail;
      return Result::BadTag;
    }
    uint8_t block[16];
    detail::counterBlock(pkt, block);
    if (!crypto::aes128Ctr(keys_.enc, block, pkt + SEC_HEADER_BYTES, plain, PLAIN_BYTES)) {
      ++authFail;
      return Result::BadTag;
    }
    last_ = c40;
    have_ = true;
    if (epoch > peerEpoch_) peerEpoch_ = epoch;
    ++accepted;
    ctr40 = c40;
    return Result::Ok;
  }

  uint16_t peerEpoch() const { return peerEpoch_; }

 private:
  DirKeys keys_;
  uint16_t minEpoch_ = 0;
  uint16_t peerEpoch_ = 0;
  bool have_ = false;
  uint64_t last_ = 0;
};

}  