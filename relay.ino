// Shadowcr3 Relay v3 - encrypted, authenticated push-to-talk voice over nRF24L01+
// Flash the SAME sketch on both boards, then pair them over Serial (type `help`).
// Hold PTT to talk, release to listen. Half duplex. Fail-closed: no key => no radio traffic.
//
// Libraries (Library Manager): "RF24" by TMRh20 (>= 1.4.x). Preferences and mbedtls ship with the ESP32 core.
// Board: "ESP32 Dev Module" (arduino-esp32 core 2.x or 3.x). Tunables: relay_config.h. Threat model: SECURITY.md
//
// Data path
//   TX: MIC -> ADC @8 kHz -> DC block -> high-pass -> txRing -> ADPCM frames -> TxFramer
//       -> seal (AES-128-CTR + HMAC-SHA256/32) -> nRF24
//   RX: nRF24 -> open (replay check, tag check, decrypt) -> depacketizer (loss recovery)
//       -> rxRing (jitter buffer) -> volume -> DAC @8 kHz -> amp
//
// Threads
//   core 0, audioTask : woken by a hardware timer every 125 us; touches ADC/DAC only
//   core 1, loop()    : PTT, buttons, serial, SPI/radio, ADPCM, crypto, housekeeping
// The two sides talk only through lock-free SPSC rings. The audio task never sees key material.

#include <Preferences.h>
#include <RF24.h>
#include <SPI.h>
#include <string.h>

#if __has_include("bootloader_random.h")
#include "bootloader_random.h"
#define RELAY_HAVE_HW_RNG 1
#endif
#if __has_include("esp_flash_encrypt.h")
#include "esp_flash_encrypt.h"
#define RELAY_HAVE_FLASH_ENC_API 1
#endif

#include "relay_adpcm.h"
#include "relay_cli.h"
#include "relay_config.h"
#include "relay_dsp.h"
#include "relay_power.h"
#include "relay_proto.h"
#include "relay_secure.h"
#include "spsc_ring.h"

using namespace relay;

using Ring = SpscRing<int16_t, RING_SIZE>;

static RF24 radio(PIN_NRF_CE, PIN_NRF_CSN);
static Preferences prefs;     // namespace "relay"    : volume
static Preferences secPrefs;  // namespace "relaysec" : master key, role, epochs
static Ring txRing;
static Ring rxRing;
static TxFramer framer;
static RxDepacketizer<Ring> depacketizer;
static Playout<Ring> playout;
static ToneGen tone;
static BatteryMonitor battery;

// Security state (core 1 only)
static bool secureReady = false;   // key loaded and keys derived
static bool txEpochOk = false;     // epoch persisted; transmitting is allowed
static Role role = Role::A;
static SessionKeys sessionKeys;
static SecureTx secTx;
static SecureRx secRx;
static uint16_t storedPeerEpoch = 0;
static bool peerEpochDirty = false;

enum class Mode : uint8_t { Rx, Tx, Switching };
static volatile Mode mode = Mode::Rx;

enum class Beep : uint8_t { None, Ready, Roger, LowBatt, Critical, VolTick, Denied, Alert };
static volatile Beep beepRequest = Beep::None;

static volatile uint8_t volumeLevel = DEFAULT_VOLUME;
static volatile uint32_t batteryMv = 0;  // written by the audio task, 0 = no reading yet

static TaskHandle_t audioTaskHandle = nullptr;
static hw_timer_t *sampleTimer = nullptr;

static volatile uint32_t audioOverruns = 0;  // sample ticks the audio task failed to service
static volatile uint32_t txOverflows = 0;    // mic samples dropped because txRing was full
static uint32_t txPackets = 0;
static uint32_t radioResets = 0;
static bool rxWasActive = false;
static bool txExhaustedReported = false;

// ------------------------------------------------------------------ audio task (core 0)

static void IRAM_ATTR onSampleTimer() {
  BaseType_t woken = pdFALSE;
  if (audioTaskHandle) vTaskNotifyGiveFromISR(audioTaskHandle, &woken);
  if (woken) portYIELD_FROM_ISR();
}

static void startBeep(Beep b) {
  switch (b) {
    case Beep::Ready:    tone.start(600, 80, 900, 80); break;
    case Beep::Roger:    tone.start(1000, 70); break;
    case Beep::LowBatt:  tone.start(800, 120, 600, 120); break;
    case Beep::Critical: tone.start(900, 90, 450, 200); break;
    case Beep::VolTick:  tone.start(static_cast<uint16_t>(400 + 100 * volumeLevel), 40); break;
    case Beep::Denied:   tone.start(300, 150, 200, 250); break;
    case Beep::Alert:    tone.start(1500, 80, 1000, 80); break;
    default: break;
  }
}

#if RELAY_ENABLE_BATTERY_MONITOR
// Once per second, average 16 consecutive RX-idle ticks of the ADC (never while transmitting).
static void sampleBattery() {
  static uint32_t tick = 0, acc = 0, n = 0;
  if (++tick < SAMPLE_RATE_HZ) return;
  acc += analogReadMilliVolts(PIN_BATT);
  if (++n == 16) {
    batteryMv = (acc / 16) * BATT_DIVIDER_RATIO_X100 / 100;
    tick = acc = n = 0;
  }
}
#endif

static void audioTask(void *) {
  DcBlocker dc;
  HighPass hpf;
  hpf.init(HPF_CUTOFF_HZ, SAMPLE_RATE_HZ);
  constexpr float kMicGain = MIC_GAIN_X8 / 8.0f;
  Mode last = Mode::Rx;

  for (;;) {
    const uint32_t ticks = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    if (ticks > 1) audioOverruns += ticks - 1;

    const Mode m = mode;
    switch (m) {
      case Mode::Tx: {
        const int raw = analogRead(PIN_MIC);
        if (last != Mode::Tx) {  // fresh transmission: start settled, no startup thump
          dc.seed(raw);
          hpf.reset();
        }
        float x = hpf.process(static_cast<float>(dc.process(raw))) * kMicGain;
        if (x > 32767.0f) x = 32767.0f;
        if (x < -32768.0f) x = -32768.0f;
        if (!txRing.push(static_cast<int16_t>(x))) ++txOverflows;
        break;
      }
      case Mode::Rx: {
        if (beepRequest != Beep::None && !tone.active() && !playout.playing()) {
          startBeep(beepRequest);
          beepRequest = Beep::None;
        }
        const int pcm = tone.active() ? tone.next() : playout.next(rxRing, PREBUFFER_SAMPLES);
        const int out = 128 + ((pcm * static_cast<int>(volumeLevel)) >> 11);
        dacWrite(PIN_SPK_DAC, constrain(out, 0, 255));
#if RELAY_ENABLE_BATTERY_MONITOR
        if (!playout.playing()) sampleBattery();
#endif
        break;
      }
      default:
        break;  // Switching: leave ADC/DAC and rings alone
    }
    last = m;
  }
}

static void startSampleTimer() {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  sampleTimer = timerBegin(1000000);  // 1 MHz tick
  timerAttachInterrupt(sampleTimer, &onSampleTimer);
  timerAlarm(sampleTimer, SAMPLE_PERIOD_US, true, 0);
#else
  sampleTimer = timerBegin(0, 80, true);  // 80 MHz / 80 = 1 MHz tick
  timerAttachInterrupt(sampleTimer, &onSampleTimer, true);
  timerAlarmWrite(sampleTimer, SAMPLE_PERIOD_US, true);
  timerAlarmEnable(sampleTimer);
#endif
}

// ------------------------------------------------------------------ keys and persistence (core 1)

static const char *roleName(Role r) { return r == Role::A ? "a" : "b"; }

static bool flashEncryptionOn() {
#ifdef RELAY_HAVE_FLASH_ENC_API
  return esp_flash_encryption_enabled();
#else
  return false;
#endif
}

// Reads the key from flash, derives all session keys, bumps and persists the transmit epoch.
static bool loadSecurity() {
  secureReady = false;
  txEpochOk = false;
  uint8_t master[KEY_BYTES];
  if (secPrefs.getBytesLength("mk") != KEY_BYTES || secPrefs.getBytes("mk", master, KEY_BYTES) != KEY_BYTES)
    return false;
  const uint8_t r = secPrefs.getUChar("role", 255);
  if (r > 1) {
    crypto::secureZero(master, sizeof master);
    return false;
  }
  role = static_cast<Role>(r);
  const bool derived = deriveSessionKeys(master, role, sessionKeys);
  crypto::secureZero(master, sizeof master);
  if (!derived) return false;

  // Epoch: persisted BEFORE the first packet of this boot, so a (key, epoch, counter) nonce can
  // never repeat even across power cuts. If the write fails, receiving still works but TX stays off.
  uint16_t epoch = secPrefs.getUShort("epoch", 0);
  if (epoch < EPOCH_MAX) {
    ++epoch;
    txEpochOk = secPrefs.putUShort("epoch", epoch) == sizeof(uint16_t);
  }
  secTx.init(sessionKeys.tx, epoch);

  storedPeerEpoch = secPrefs.getUShort("peerEp", 0);
  secRx.init(sessionKeys.rx, storedPeerEpoch);
  peerEpochDirty = false;
  secureReady = true;
  return true;
}

// Stores a new master key. Re-entering the SAME key and role keeps the epoch counters, so
// re-provisioning one side does not lock it out of the other.
static bool storeKey(const uint8_t *key, Role r) {
  uint8_t old[KEY_BYTES];
  const bool same = secPrefs.getBytesLength("mk") == KEY_BYTES &&
                    secPrefs.getBytes("mk", old, KEY_BYTES) == KEY_BYTES && crypto::ctEqual(old, key, KEY_BYTES) &&
                    secPrefs.getUChar("role", 255) == static_cast<uint8_t>(r);
  crypto::secureZero(old, sizeof old);
  if (!same) {
    const bool ok = secPrefs.putBytes("mk", key, KEY_BYTES) == KEY_BYTES &&
                    secPrefs.putUChar("role", static_cast<uint8_t>(r)) == 1 &&
                    secPrefs.putUShort("epoch", 0) == 2 && secPrefs.putUShort("peerEp", 0) == 2;
    if (!ok) return false;
  }
  return loadSecurity();
}

static void clearKey() {
  secPrefs.remove("mk");
  secPrefs.remove("role");
  secPrefs.remove("epoch");
  secPrefs.remove("peerEp");
  secureReady = false;
  txEpochOk = false;
  crypto::secureZero(&sessionKeys, sizeof sessionKeys);
  secTx.init(sessionKeys.tx, 0);
  secRx.init(sessionKeys.rx, 0);
}

static bool generateKey(uint8_t *key) {
#ifdef RELAY_HAVE_HW_RNG
  // Without Wi-Fi/Bluetooth running, esp_random() is only pseudo-random. The bootloader RNG mode
  // feeds the generator from the SAR ADC noise source, so call it explicitly for key material.
  bootloader_random_enable();
  esp_fill_random(key, KEY_BYTES);
  bootloader_random_disable();
  return true;
#else
  (void)key;
  return false;
#endif
}

// ------------------------------------------------------------------ radio side (core 1)

static bool initRadio() {
  if (!radio.begin(&SPI) || !radio.isChipConnected()) return false;
  radio.setAutoAck(false);  // broadcast-style: no ACK, no retransmit
  radio.disableDynamicPayloads();
  radio.setPayloadSize(PACKET_SIZE);
  radio.setAddressWidth(5);
  radio.setCRCLength(RF24_CRC_16);  // corrupted packets are dropped, never played
  const rf24_datarate_e rate = RF_DATA_RATE_KBPS == 250    ? RF24_250KBPS
                               : RF_DATA_RATE_KBPS == 2000 ? RF24_2MBPS
                                                           : RF24_1MBPS;
  if (!radio.setDataRate(rate)) Serial.println("warning: data rate not supported (clone chip?)");
  radio.setChannel(RF_CHANNEL);
  static const rf24_pa_dbm_e kPa[4] = {RF24_PA_MIN, RF24_PA_LOW, RF24_PA_HIGH, RF24_PA_MAX};
  radio.setPALevel(kPa[RF_PA_LEVEL & 3]);
  if (!secureReady) {  // fail closed: no key, no radio activity
    radio.powerDown();
    return true;
  }
  radio.openWritingPipe(sessionKeys.addr);  // address derived from the key, not hard-coded
  radio.openReadingPipe(1, sessionKeys.addr);
  radio.startListening();
  return true;
}

static void pumpTx() {
  int16_t pcm[FRAME_SAMPLES];
  uint8_t plain[PLAIN_BYTES];
  uint8_t pkt[PACKET_SIZE];
  while (txRing.size() >= FRAME_SAMPLES) {
    for (uint8_t i = 0; i < FRAME_SAMPLES; ++i) txRing.pop(pcm[i]);
    if (!framer.push(pcm, plain)) continue;  // first frame of the burst only primes the pipeline
    if (!secTx.seal(plain, pkt)) {           // counter exhausted: stop rather than ever reuse a nonce
      txExhaustedReported = true;
      continue;
    }
    radio.write(pkt, PACKET_SIZE);  // auto-ack is off, so this only waits for the packet to leave
    ++txPackets;
  }
}

static void pumpRx() {
  uint8_t pkt[PACKET_SIZE];
  uint8_t plain[PLAIN_BYTES];
  while (radio.available()) {  // RX FIFO holds only 3 packets (~7 ms): keep loop() tight
    radio.read(pkt, PACKET_SIZE);
    uint64_t ctr = 0;
    if (secRx.open(pkt, plain, ctr) == SecureRx::Result::Ok) {
      depacketizer.onFrames(ctr, plain, rxRing, millis());
      if (secRx.peerEpoch() > storedPeerEpoch) peerEpochDirty = true;
    }
  }
  const bool active = depacketizer.burstActive(millis());
  if (rxWasActive && !active) beepRequest = Beep::Roger;  // far side let go of PTT
  rxWasActive = active;
}

static void enterTx() {
  mode = Mode::Switching;
  delay(1);  // >> one sample tick: audio task has seen Switching and is idle
  radio.stopListening();
  txRing.reset();
  framer.reset();
  mode = Mode::Tx;
}

static void enterRx() {
  mode = Mode::Switching;
  delay(1);
  pumpTx();  // flush whole frames still queued from the last few ms of speech
  if (secureReady) radio.startListening();
  rxRing.reset();
  depacketizer.reset();
  playout.reset();
  rxWasActive = false;
  dacWrite(PIN_SPK_DAC, 128);  // mid-rail, avoids a DC step into the amp
  mode = Mode::Rx;
}

// ------------------------------------------------------------------ inputs and housekeeping

struct Debounced {
  explicit Debounced(uint8_t p) : pin(p) {}
  // Returns true once per press (on the falling edge, after 20 ms of stability).
  bool pressed(uint32_t now) {
    const bool raw = digitalRead(pin) == LOW;
    if (raw != lastRaw) {
      lastRaw = raw;
      changedAt = now;
    }
    if (raw != stable && now - changedAt >= 20) {
      stable = raw;
      return stable;
    }
    return false;
  }
  uint8_t pin;
  bool stable = false, lastRaw = false;
  uint32_t changedAt = 0;
};

static void pollPtt(uint32_t now) {
  static bool stable = false, lastRaw = false;
  static uint32_t changedAt = 0;
  const bool raw = digitalRead(PIN_PTT) == LOW;
  if (raw != lastRaw) {
    lastRaw = raw;
    changedAt = now;
  }
  if (raw != stable && now - changedAt >= 20) {  // 20 ms debounce
    stable = raw;
    if (stable) {
      if (secureReady && txEpochOk && mode == Mode::Rx)
        enterTx();
      else
        beepRequest = Beep::Denied;  // no key (or no persisted epoch): refuse to transmit
    } else if (mode == Mode::Tx) {
      enterRx();
    }
  }
}

static void pollVolume(uint32_t now) {
  static Debounced up(PIN_VOL_UP), down(PIN_VOL_DOWN);
  static bool dirty = false;
  static uint32_t changedAt = 0;

  const bool u = up.pressed(now);
  const bool d = down.pressed(now);
  uint8_t v = volumeLevel;
  if (u && v < MAX_VOLUME) ++v;
  if (d && v > 0) --v;
  if (v != volumeLevel) {
    volumeLevel = v;
    beepRequest = Beep::VolTick;
    dirty = true;
    changedAt = now;
  }
  // Flash writes stall the whole chip for a few ms: only persist while idle.
  if (dirty && now - changedAt > 3000 && mode == Mode::Rx && !depacketizer.burstActive(now)) {
    prefs.putUChar("vol", volumeLevel);
    dirty = false;
  }
}

static void pollBattery(uint32_t now) {
#if RELAY_ENABLE_BATTERY_MONITOR
  static uint32_t last = 0, lastCritical = 0;
  if (now - last < 1000) return;
  last = now;
  const uint32_t mv = batteryMv;
  if (mode != Mode::Rx || mv == 0) return;
  const BatteryLevel before = battery.level();
  const BatteryLevel after = battery.update(mv);
  if (after != before && after != BatteryLevel::Ok) {
    beepRequest = after == BatteryLevel::Critical ? Beep::Critical : Beep::LowBatt;
  } else if (after == BatteryLevel::Critical && now - lastCritical > 60000) {
    lastCritical = now;
    beepRequest = Beep::Critical;
  }
#else
  (void)now;
#endif
}

// Intrusion alarm: a flood of packets that pass the radio CRC but fail authentication is someone
// transmitting on our address without the key (or replaying captured traffic).
static void pollSecurity(uint32_t now) {
  static uint32_t last = 0, lastBad = 0, lastAlert = 0;
  if (!secureReady || now - last < 1000) return;
  last = now;
  const uint32_t bad = secRx.authFail + secRx.replays;
  const uint32_t delta = bad - lastBad;
  lastBad = bad;
  const bool idle = mode == Mode::Rx && !depacketizer.burstActive(now);
  if (delta >= AUTH_ALERT_THRESHOLD && now - lastAlert > 30000) {
    lastAlert = now;
    beepRequest = Beep::Alert;
    if (idle) Serial.printf("SECURITY ALERT: %lu invalid packets in 1 s\n", (unsigned long)delta);
  }
  // Persist the highest peer epoch seen (flash write: idle only).
  if (peerEpochDirty && idle) {
    storedPeerEpoch = secRx.peerEpoch();
    secPrefs.putUShort("peerEp", storedPeerEpoch);
    peerEpochDirty = false;
  }
}

static void updateLed(uint32_t now) {
  bool on = false;
  if (mode == Mode::Tx) {
    on = true;
  } else if (!secureReady) {
    on = (now % 400) < 200;  // fast blink: not paired
  } else {
    switch (battery.level()) {
      case BatteryLevel::Low:      on = (now % 3000) < 100; break;
      case BatteryLevel::Critical: on = (now % 500) < 100; break;
      default: break;
    }
  }
  digitalWrite(PIN_LED, on ? HIGH : LOW);
}

static void checkRadio(uint32_t now) {
  static uint32_t last = 0;
  if (now - last < 2000) return;
  last = now;
  if (!secureReady || mode != Mode::Rx || depacketizer.burstActive(now)) return;
  if (!radio.isChipConnected()) {  // brown-out or loose wire: recover without a reboot
    ++radioResets;
    initRadio();
  }
}

static void printStatus() {
  char fp[9] = "--------";
  if (secureReady) toHex(sessionKeys.fingerprint, 4, fp);
  Serial.printf("paired=%s role=%s fp=%s txEpoch=%s peerEpoch=%u flashEnc=%s\n", secureReady ? "yes" : "NO",
                secureReady ? roleName(role) : "-", fp, txEpochOk ? "ok" : "off", (unsigned)storedPeerEpoch,
                flashEncryptionOn() ? "on" : "OFF (keys readable from flash)");
}

static void printStats(uint32_t now) {
  static uint32_t last = 0;
  if (now - last < 2000) return;
  if (mode == Mode::Rx && depacketizer.burstActive(now)) return;  // never stall RX mid-burst
  last = now;
  if (!secureReady) {
    Serial.println("NOT PAIRED: radio is off. Use `key set <32 hex> <a|b>` or `key gen` (type `help`).");
    return;
  }
  const auto &s = depacketizer.stats;
  Serial.printf("[%s] tx=%lu rx=%lu rec=%lu lost=%lu drop=%lu bursts=%lu bad=%lu replay=%lu ovr=%lu vol=%u bat=%lumV rst=%lu\n",
                mode == Mode::Tx ? "TX" : "RX", (unsigned long)txPackets, (unsigned long)s.packets,
                (unsigned long)s.recovered, (unsigned long)s.concealedFrames,
                (unsigned long)s.droppedHighWater, (unsigned long)s.bursts, (unsigned long)secRx.authFail,
                (unsigned long)secRx.replays, (unsigned long)audioOverruns, (unsigned)volumeLevel,
                (unsigned long)batteryMv, (unsigned long)radioResets);
  if (txExhaustedReported) Serial.println("TX counter exhausted: reboot the transmitter to start a new epoch.");
}

// ------------------------------------------------------------------ serial provisioning

static void handleCommand(const char *line, uint32_t now) {
  Command cmd = parseCommand(line);
  if (cmd.type == Command::None) return;
  if (mode != Mode::Rx || depacketizer.burstActive(now)) {
    Serial.println("busy: release PTT / wait for the channel to go idle");
    crypto::secureZero(cmd.key, sizeof cmd.key);
    return;
  }
  switch (cmd.type) {
    case Command::Help:
      Serial.println("commands: status | key set <32 hex> <a|b> | key gen | key clear");
      Serial.println("one device is role a, the other role b, both with the SAME key");
      break;
    case Command::Status:
      printStatus();
      break;
    case Command::KeySet:
      if (storeKey(cmd.key, cmd.role) && initRadio()) {
        Serial.print("key stored. ");
        printStatus();
      } else {
        Serial.println("error: could not store key");
      }
      break;
    case Command::KeyGen: {
      uint8_t key[KEY_BYTES];
      mode = Mode::Switching;  // keep the ADC quiet while the RNG owns it
      delay(2);
      const bool have = generateKey(key);
      mode = Mode::Rx;
      if (!have) {
        Serial.println("no hardware RNG API in this core: generate on a PC with `openssl rand -hex 16`");
        break;
      }
      if (storeKey(key, Role::A) && initRadio()) {
        char hex[2 * KEY_BYTES + 1];
        toHex(key, KEY_BYTES, hex);
        Serial.println("key generated, this device is role a. On the OTHER device type exactly:");
        Serial.printf("key set %s b\n", hex);
        Serial.println("(this text is the secret: clear your terminal history afterwards)");
        crypto::secureZero(hex, sizeof hex);
      } else {
        Serial.println("error: could not store key");
      }
      crypto::secureZero(key, sizeof key);
      break;
    }
    case Command::KeyClear:
      clearKey();
      initRadio();
      Serial.println("key wiped. Radio is off until a new key is set.");
      break;
    case Command::BadArgs:
      Serial.println("bad arguments. usage: key set <32 hex chars> <a|b>");
      break;
    default:
      Serial.println("unknown command, try `help`");
      break;
  }
  crypto::secureZero(cmd.key, sizeof cmd.key);
}

static void pollSerial(uint32_t now) {
  static char line[96];
  static size_t len = 0;
  static bool overflow = false;
  while (Serial.available()) {
    const char c = static_cast<char>(Serial.read());
    if (c == '\r' || c == '\n') {
      if (len && !overflow) {
        line[len] = '\0';
        handleCommand(line, now);
      }
      crypto::secureZero(line, sizeof line);  // the line may have held a key
      len = 0;
      overflow = false;
    } else if (len < sizeof(line) - 1) {
      line[len++] = c;
    } else {
      overflow = true;
    }
  }
}

[[noreturn]] static void fatal(const char *msg) {
  Serial.println(msg);
  for (;;) {
    digitalWrite(PIN_LED, !digitalRead(PIN_LED));
    delay(150);
  }
}

// ------------------------------------------------------------------ Arduino entry points

void setup() {
  Serial.begin(115200);
  pinMode(PIN_PTT, INPUT_PULLUP);
  pinMode(PIN_VOL_UP, INPUT_PULLUP);
  pinMode(PIN_VOL_DOWN, INPUT_PULLUP);
  pinMode(PIN_LED, OUTPUT);

  analogReadResolution(12);
  analogSetPinAttenuation(PIN_MIC, ADC_11db);  // ~0-3.1 V full scale
#if RELAY_ENABLE_BATTERY_MONITOR
  analogSetPinAttenuation(PIN_BATT, ADC_11db);
#endif
  dacWrite(PIN_SPK_DAC, 128);

  prefs.begin("relay", false);
  volumeLevel = prefs.getUChar("vol", DEFAULT_VOLUME);
  if (volumeLevel > MAX_VOLUME) volumeLevel = DEFAULT_VOLUME;

  secPrefs.begin("relaysec", false);
  loadSecurity();  // false = not paired yet; the device then stays silent

  SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI, PIN_NRF_CSN);
  if (!initRadio())
    fatal("nRF24 not found: check wiring, 3.3 V supply and the 10-100 uF cap on the module");

  xTaskCreatePinnedToCore(audioTask, "audio", 4096, nullptr, configMAX_PRIORITIES - 2,
                          &audioTaskHandle, 0);
  startSampleTimer();
  if (secureReady) beepRequest = Beep::Ready;

  Serial.println("Shadowcr3 Relay v3 (secure)");
  printStatus();
  if (!flashEncryptionOn())
    Serial.println("warning: flash encryption is off, so the pairing key can be read out over USB (see SECURITY.md)");
}

void loop() {
  const uint32_t now = millis();
  pollSerial(now);
  pollPtt(now);
  if (mode == Mode::Tx)
    pumpTx();
  else if (mode == Mode::Rx && secureReady)
    pumpRx();
  pollVolume(now);
  pollBattery(now);
  pollSecurity(now);
  updateLed(now);
  checkRadio(now);
  printStats(now);
}
