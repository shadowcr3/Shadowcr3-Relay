#pragma once
#include <atomic>
#include <stddef.h>
#include <stdint.h>

template <typename T, size_t N>
class SpscRing {
  static_assert(N && (N & (N - 1)) == 0, "N must be a power of two");

 public:
  bool push(T v) {
    const uint32_t h = head_.load(std::memory_order_relaxed);
    const uint32_t t = tail_.load(std::memory_order_acquire);
    if (h - t >= N) return false;
    buf_[h & (N - 1)] = v;
    head_.store(h + 1, std::memory_order_release);
    return true;
  }

  bool pop(T &v) {
    const uint32_t t = tail_.load(std::memory_order_relaxed);
    const uint32_t h = head_.load(std::memory_order_acquire);
    if (h == t) return false;
    v = buf_[t & (N - 1)];
    tail_.store(t + 1, std::memory_order_release);
    return true;
  }

  
  size_t size() const {
    const uint32_t t = tail_.load(std::memory_order_acquire);
    const uint32_t h = head_.load(std::memory_order_acquire);
    return h - t;
  }

  
  void reset() {
    head_.store(0, std::memory_order_relaxed);
    tail_.store(0, std::memory_order_relaxed);
  }

 private:
  T buf_[N];
  std::atomic<uint32_t> head_{0};
  std::atomic<uint32_t> tail_{0};
};
