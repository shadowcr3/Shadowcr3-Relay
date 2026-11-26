#pragma once
#include <stdint.h>

#include "relay_config.h"

namespace relay {

static const int16_t kAdpcmStep[89] = {
    7,     8,     9,     10,    11,    12,    13,    14,    16,    17,    19,    21,    23,
    25,    28,    31,    34,    37,    41,    45,    50,    55,    60,    66,    73,    80,
    88,    97,    107,   118,   130,   143,   157,   173,   190,   209,   230,   253,   279,
    307,   337,   371,   408,   449,   494,   544,   598,   658,   724,   796,   876,   963,
    1060,  1166,  1282,  1411,  1552,  1707,  1878,  2066,  2272,  2499,  2749,  3024,  3327,
    3660,  4026,  4428,  4871,  5358,  5894,  6484,  7132,  7845,  8630,  9493,  10442, 11487,
    12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767};

static const int8_t kAdpcmIndex[16] = {-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8};

struct AdpcmState {
  int pred = 0;
  int idx = 0;
};

inline void adpcmApply(AdpcmState &s, uint8_t nib) {
  const int step = kAdpcmStep[s.idx];
  int vpdiff = step >> 3;
  if (nib & 4) vpdiff += step;
  if (nib & 2) vpdiff += step >> 1;
  if (nib & 1) vpdiff += step >> 2;
  s.pred += (nib & 8) ? -vpdiff : vpdiff;
  if (s.pred > 32767) s.pred = 32767;
  else if (s.pred < -32768) s.pred = -32768;
  s.idx += kAdpcmIndex[nib];
  if (s.idx < 0) s.idx = 0;
  else if (s.idx > 88) s.idx = 88;
}

inline void adpcmPackState(const AdpcmState &s, uint8_t *out3) {
  out3[0] = static_cast<uint8_t>(s.pred & 0xFF);
  out3[1] = static_cast<uint8_t>((s.pred >> 8) & 0xFF);
  out3[2] = static_cast<uint8_t>(s.idx);
}

inline AdpcmState adpcmUnpackState(const uint8_t *in3) {
  AdpcmState s;
  s.pred = static_cast<int16_t>(static_cast<uint16_t>(in3[0] | (in3[1] << 8)));
  s.idx = in3[2] > 88 ? 88 : in3[2]; 
  return s;
}

class AdpcmEncoder {
 public:
  void reset() { state_ = AdpcmState(); }
  const AdpcmState &state() const { return state_; }

  void encodeData(const int16_t *pcm, uint8_t *out) {
    for (int i = 0; i < FRAME_SAMPLES; i += 2) {
      const uint8_t lo = encodeSample(pcm[i]);
      const uint8_t hi = encodeSample(pcm[i + 1]);
      out[i / 2] = static_cast<uint8_t>(lo | (hi << 4));
    }
  }

 private:
  uint8_t encodeSample(int16_t sample) {
    int step = kAdpcmStep[state_.idx];
    int diff = sample - state_.pred;
    uint8_t nib = 0;
    if (diff < 0) {
      nib = 8;
      diff = -diff;
    }
    if (diff >= step) {
      nib |= 4;
      diff -= step;
    }
    step >>= 1;
    if (diff >= step) {
      nib |= 2;
      diff -= step;
    }
    step >>= 1;
    if (diff >= step) nib |= 1;
    adpcmApply(state_, nib);
    return nib;
  }

  AdpcmState state_;
};

inline void adpcmDecodeData(AdpcmState &st, const uint8_t *in, int16_t *out) {
  for (int i = 0; i < FRAME_DATA_BYTES; ++i) {
    adpcmApply(st, in[i] & 0x0F);
    out[2 * i] = static_cast<int16_t>(st.pred);
    adpcmApply(st, in[i] >> 4);
    out[2 * i + 1] = static_cast<int16_t>(st.pred);
  }
}

}  
