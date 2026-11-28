#pragma once
#include <stdint.h>

#include "relay_config.h"

namespace relay {

enum class BatteryLevel : uint8_t { Ok, Low, Critical };

class BatteryMonitor {
 public:
  BatteryLevel level() const { return level_; }

  BatteryLevel update(uint32_t mv) {
    if (mv < BATT_CRITICAL_MV) {
      level_ = BatteryLevel::Critical;
    } else if (level_ == BatteryLevel::Critical) {
      if (mv > BATT_CRITICAL_MV + BATT_HYST_MV) level_ = BatteryLevel::Low;  
    } else if (level_ == BatteryLevel::Low) {
      if (mv > BATT_LOW_MV + BATT_HYST_MV) level_ = BatteryLevel::Ok;
    } else if (mv < BATT_LOW_MV) {
      level_ = BatteryLevel::Low;
    }
    return level_;
  }

 private:
  BatteryLevel level_ = BatteryLevel::Ok;
};

}