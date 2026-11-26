#pragma once
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "relay_config.h"
#include "relay_secure.h"

namespace relay {

struct Command {
  enum Type : uint8_t { None, Help, Status, KeySet, KeyGen, KeyClear, BadArgs, Unknown };
  Type type = None;
  uint8_t key[KEY_BYTES] = {0};
  Role role = Role::A;
};

inline int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline bool parseHex(const char *s, size_t nBytes, uint8_t *out) {
  if (strlen(s) != nBytes * 2) return false;
  for (size_t i = 0; i < nBytes; ++i) {
    const int hi = hexVal(s[2 * i]);
    const int lo = hexVal(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>(hi * 16 + lo);
  }
  return true;
}

inline void toHex(const uint8_t *in, size_t n, char *out) { 
  static const char kDigits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = kDigits[in[i] >> 4];
    out[2 * i + 1] = kDigits[in[i] & 0x0F];
  }
  out[2 * n] = '\0';
}

inline Command parseCommand(const char *line) {
  Command cmd;
  char buf[96];
  const size_t n = strlen(line);
  if (n >= sizeof(buf)) {
    cmd.type = Command::BadArgs;
    return cmd;
  }
  memcpy(buf, line, n + 1);

  char *tok[5];
  size_t count = 0;
  char *p = buf;
  while (*p && count < 5) {
    while (*p == ' ' || *p == '\t') *p++ = '\0';
    if (!*p) break;
    tok[count++] = p;
    while (*p && *p != ' ' && *p != '\t') ++p;
  }
  if (count == 0) return cmd;
  for (char *c = tok[0]; *c; ++c) *c = static_cast<char>(tolower(static_cast<unsigned char>(*c)));

  if (strcmp(tok[0], "help") == 0) {
    cmd.type = Command::Help;
  } else if (strcmp(tok[0], "status") == 0) {
    cmd.type = Command::Status;
  } else if (strcmp(tok[0], "key") == 0 && count >= 2) {
    for (char *c = tok[1]; *c; ++c) *c = static_cast<char>(tolower(static_cast<unsigned char>(*c)));
    if (strcmp(tok[1], "gen") == 0 && count == 2) {
      cmd.type = Command::KeyGen;
    } else if (strcmp(tok[1], "clear") == 0 && count == 2) {
      cmd.type = Command::KeyClear;
    } else if (strcmp(tok[1], "set") == 0) {
      cmd.type = Command::BadArgs;
      if (count == 4 && parseHex(tok[2], KEY_BYTES, cmd.key) && strlen(tok[3]) == 1) {
        const char r = static_cast<char>(tolower(static_cast<unsigned char>(tok[3][0])));
        if (r == 'a' || r == 'b') {
          cmd.role = r == 'a' ? Role::A : Role::B;
          cmd.type = Command::KeySet;
        }
      }
    } else {
      cmd.type = Command::Unknown;
    }
  } else {
    cmd.type = Command::Unknown;
  }
  crypto::secureZero(buf, sizeof buf);  
  if (cmd.type != Command::KeySet) crypto::secureZero(cmd.key, sizeof cmd.key);  
  return cmd;
}

}  