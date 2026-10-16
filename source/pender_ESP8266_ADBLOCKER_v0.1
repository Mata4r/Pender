/*
 * ESP8266 DNS Ad Blocker - "pender" edition
 * Board: NodeMCU 1.0 / Wemos D1 mini (ESP8266 Arduino core 3.x)
 *
 * What it does:
 * - Hosts its own Wi-Fi network called "pender" (access point).
 * - Devices that join "pender" get this ESP8266 as their DNS server.
 * - A web page (http://192.168.4.1) lets you enter the SSID and password of
 *   your real Wi-Fi network. It is saved to flash and used for the uplink.
 * - Blocked ad/tracker lookups are sinkholed locally; everything else is
 *   forwarded to AdGuard DNS through the uplink.
 * - Dashboard shows a stacked bar chart of blocked lookups over the last hour.
 *
 * Notes:
 * - Change AP_PASS below. Use "" for an open network (not recommended).
 *   WPA2 passwords must be 8-63 characters.
 * - The Wi-Fi setup page only works from devices connected to "pender".
 * - ENABLE_NAPT lets devices on "pender" reach the internet through the uplink
 *   (the ESP8266 acts as a small router). Set it to 0 if it does not compile
 *   with your lwIP variant; DNS filtering still works, but "pender" clients
 *   will have no internet access without it.
 * - Website username and password can be changed in the protected Settings page.
 * - Do not expose the web UI to the internet.
 */

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <WiFiUdp.h>
#include <EEPROM.h>
#include <string.h>
#include <time.h>

#define ENABLE_NAPT 1
#if ENABLE_NAPT
#include <lwip/napt.h>
#endif
#ifndef SOFTAP_IF
#define SOFTAP_IF 1
#endif

// ---------- Access point ("pender") ----------
const char* AP_SSID = "pender";
const char* AP_PASS = "pender123";   // 8-63 chars, or "" for an open network

// Website login is disabled until the user sets a username/password on the website.
static const uint32_t AUTH_MAGIC = 0x50415536;  // v6: clear any older saved website login once
struct SiteAuthCfg {
  uint32_t magic;
  char user[33];
  char pass[64];
};
SiteAuthCfg siteAuth;
IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_MASK(255, 255, 255, 0);

// AdGuard DNS default filtering resolver.
IPAddress UPSTREAM_DNS(94, 140, 14, 14);

static const uint16_t DNS_PORT = 53;
static const size_t DNS_BUF = 768;
static const uint8_t MAX_PENDING = 16;
static const uint32_t PENDING_TIMEOUT_MS = 3500;
static const uint32_t BLOCK_TTL = 60;

WiFiUDP dnsSocket;
WiFiUDP upstreamSocket;
ESP8266WebServer web(80);

uint8_t packet[DNS_BUF];
uint8_t response[DNS_BUF];

// ---------- Saved uplink Wi-Fi credentials ----------
struct WifiCfg {
  uint32_t magic;
  char ssid[33];
  char pass[64];
};
static const uint32_t CFG_MAGIC = 0x50454E44;  // "PEND"
WifiCfg cfg;
bool connectRequested = false;
uint32_t lastAttempt = 0;

// ---------- Scheduled restart ----------
// A daily restart clears fragmented heap so the ESP8266 does not crash after
// weeks of running. Time of day comes from NTP over the uplink Wi-Fi, so the
// schedule only fires once the clock has synced.
struct RestartCfg {
  uint32_t magic;
  uint8_t enabled;
  uint8_t hour;       // 0-23
  uint8_t minute;     // 0-59
  int8_t tzHalfHrs;   // timezone offset in half-hour steps (UTC+3 = 6)
};
static const uint32_t RESTART_MAGIC = 0x52535431;  // "RST1"
RestartCfg rcfg;
bool restartNowPending = false;
uint32_t restartNowAt = 0;
static const time_t CLOCK_VALID_AFTER = 1700000000;  // any time before this means "not synced"

bool clockSynced() { return time(nullptr) > CLOCK_VALID_AFTER; }

void startClock() {
  configTime((long)rcfg.tzHalfHrs * 1800L, 0, "pool.ntp.org", "time.google.com");
}

#if ENABLE_NAPT
bool naptInit = false;
bool naptOn = false;
#endif

bool hasCreds() {
  return cfg.magic == CFG_MAGIC && cfg.ssid[0] != '\0';
}

void loadCfg() {
  EEPROM.begin(sizeof(WifiCfg) + sizeof(SiteAuthCfg) + sizeof(RestartCfg));
  EEPROM.get(0, cfg);
  if (cfg.magic != CFG_MAGIC) memset(&cfg, 0, sizeof(cfg));
  cfg.ssid[32] = '\0';
  cfg.pass[63] = '\0';

  EEPROM.get(sizeof(WifiCfg), siteAuth);
  // A new auth magic intentionally clears old hard-coded/saved website login
  // details once, while leaving the saved Wi-Fi configuration untouched.
  if (siteAuth.magic != AUTH_MAGIC) {
    memset(&siteAuth, 0, sizeof(siteAuth));
    siteAuth.magic = AUTH_MAGIC;
    EEPROM.put(sizeof(WifiCfg), siteAuth);
    EEPROM.commit();
  }
  siteAuth.user[sizeof(siteAuth.user) - 1] = '\0';
  siteAuth.pass[sizeof(siteAuth.pass) - 1] = '\0';

  // Restart schedule lives after the other two blocks, so older saved
  // settings are untouched. Not set yet -> disabled, 04:00, UTC+3.
  EEPROM.get(sizeof(WifiCfg) + sizeof(SiteAuthCfg), rcfg);
  if (rcfg.magic != RESTART_MAGIC || rcfg.hour > 23 || rcfg.minute > 59 ||
      rcfg.tzHalfHrs < -24 || rcfg.tzHalfHrs > 28) {
    memset(&rcfg, 0, sizeof(rcfg));
    rcfg.magic = RESTART_MAGIC;
    rcfg.hour = 4;
    rcfg.minute = 0;
    rcfg.tzHalfHrs = 6;
  }
}

void saveRestartCfg() {
  rcfg.magic = RESTART_MAGIC;
  EEPROM.put(sizeof(WifiCfg) + sizeof(SiteAuthCfg), rcfg);
  EEPROM.commit();
}

void saveSiteAuth(const String& user, const String& pass) {
  memset(&siteAuth, 0, sizeof(siteAuth));
  siteAuth.magic = AUTH_MAGIC;
  user.toCharArray(siteAuth.user, sizeof(siteAuth.user));
  pass.toCharArray(siteAuth.pass, sizeof(siteAuth.pass));
  EEPROM.put(sizeof(WifiCfg), siteAuth);
  EEPROM.commit();
}

void saveCfg(const String& s, const String& p) {
  memset(&cfg, 0, sizeof(cfg));
  cfg.magic = CFG_MAGIC;
  s.toCharArray(cfg.ssid, sizeof(cfg.ssid));
  p.toCharArray(cfg.pass, sizeof(cfg.pass));
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

void clearCfg() {
  memset(&cfg, 0, sizeof(cfg));
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

// ---------- DNS bookkeeping ----------
struct PendingQuery {
  bool used;
  uint16_t clientId;
  uint16_t upstreamId;
  IPAddress clientIP;
  uint16_t clientPort;
  uint32_t createdAt;
};
PendingQuery pending[MAX_PENDING];

uint32_t totalQueries = 0;
uint32_t blockedQueries = 0;
uint32_t forwardedQueries = 0;
uint32_t droppedQueries = 0;
uint32_t malformedQueries = 0;
String lastDomain = "-";

// Blocked-lookup history for the chart: 12 buckets x 5 minutes = 1 hour.
// A = IPv4 lookups blocked (green body), AAAA = IPv6 lookups blocked (purple head).
static const uint8_t BUCKETS = 12;
static const uint32_t BUCKET_MS = 300000UL;
uint16_t bucketA[BUCKETS];
uint16_t bucketAAAA[BUCKETS];
uint8_t bucketHead = 0;
uint32_t bucketStart = 0;

void rollBuckets() {
  uint32_t now = millis();
  uint8_t steps = 0;
  while ((uint32_t)(now - bucketStart) >= BUCKET_MS && steps < BUCKETS) {
    bucketHead = (bucketHead + 1) % BUCKETS;
    bucketA[bucketHead] = 0;
    bucketAAAA[bucketHead] = 0;
    bucketStart += BUCKET_MS;
    steps++;
  }
  if ((uint32_t)(now - bucketStart) >= BUCKET_MS) bucketStart = now;
}

// Lightweight client tracking: devices that sent DNS queries recently.
static const uint8_t MAX_CLIENTS = 8;
struct ClientStats {
  bool used;
  IPAddress ip;
  uint32_t queries;
  uint32_t blocked;
  uint32_t lastSeen;
};
ClientStats clients[MAX_CLIENTS];

void recordClient(IPAddress ip, bool locallyBlocked) {
  int chosen = -1;
  int oldest = 0;
  uint32_t oldestAge = 0;
  uint32_t now = millis();
  for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].used && clients[i].ip == ip) {
      chosen = i;
      break;
    }
    if (!clients[i].used) {
      chosen = i;
      break;
    }
    uint32_t age = now - clients[i].lastSeen;
    if (age >= oldestAge) { oldestAge = age; oldest = i; }
  }
  if (chosen < 0) chosen = oldest;
  if (!clients[chosen].used || clients[chosen].ip != ip) {
    clients[chosen].used = true;
    clients[chosen].ip = ip;
    clients[chosen].queries = 0;
    clients[chosen].blocked = 0;
  }
  clients[chosen].queries++;
  if (locallyBlocked) clients[chosen].blocked++;
  clients[chosen].lastSeen = now;
}

// Keep domains lowercase. Exact domains and their subdomains are blocked.
const char* BLOCKLIST[] = {
  "doubleclick.net",
  "googlesyndication.com",
  "googleadservices.com",
  "adservice.google.com",
  "adnxs.com",
  "ads.yahoo.com",
  "app-measurement.com",
  "scorecardresearch.com"
};
const size_t BLOCKLIST_COUNT = sizeof(BLOCKLIST) / sizeof(BLOCKLIST[0]);

bool endsWithDomain(const char* domain, const char* suffix) {
  if (!domain || !suffix) return false;
  size_t dl = strlen(domain), sl = strlen(suffix);
  if (dl < sl) return false;
  if (strcmp(domain + dl - sl, suffix) != 0) return false;
  return dl == sl || domain[dl - sl - 1] == '.';
}

bool isBlocked(const char* domain) {
  for (size_t i = 0; i < BLOCKLIST_COUNT; i++) {
    if (endsWithDomain(domain, BLOCKLIST[i])) return true;
  }
  return false;
}

// Parse an uncompressed DNS QNAME, rejecting compression and invalid label lengths.
// Returns offset after the terminating zero, or -1 on invalid input.
int parseQName(const uint8_t* p, int len, int off, char* out, size_t outSize) {
  if (!p || !out || outSize < 2) return -1;
  size_t outLen = 0;
  int labels = 0;

  while (true) {
    if (off >= len) return -1;
    uint8_t labelLen = p[off++];

    if (labelLen == 0) {
      out[outLen] = '\0';
      return labels > 0 ? off : -1;
    }

    if ((labelLen & 0xC0) != 0 || labelLen > 63) return -1;
    if (off + labelLen > len) return -1;
    if (outLen && outLen + 1 >= outSize) return -1;

    if (outLen) out[outLen++] = '.';
    if (outLen + labelLen >= outSize) return -1;

    for (uint8_t i = 0; i < labelLen; i++) {
      unsigned char c = p[off++];
      if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
      if (c < 0x21 || c > 0x7e) return -1;
      out[outLen++] = (char)c;
    }
    labels++;
    if (labels > 127) return -1;
  }
}

void writeU16(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xff);
}

uint16_t readU16(const uint8_t* p) {
  return ((uint16_t)p[0] << 8) | p[1];
}

void sendDnsPacket(IPAddress ip, uint16_t port, const uint8_t* data, size_t len) {
  if (len > DNS_BUF) return;
  dnsSocket.beginPacket(ip, port);
  dnsSocket.write(data, len);
  dnsSocket.endPacket();
}

// Sends a sinkhole reply for A/AAAA. For other query types, return NOERROR/NODATA.
// qEnd must point just after QNAME + QTYPE + QCLASS.
void sendBlockedReply(int qEnd, uint16_t qtype, uint16_t qclass,
                      IPAddress clientIP, uint16_t clientPort) {
  if (qEnd < 17 || qEnd > (int)DNS_BUF) return;

  memcpy(response, packet, qEnd);

  response[2] = (uint8_t)(0x80 | (packet[2] & 0x01));
  response[3] = (uint8_t)(0x80 | (packet[3] & 0x10));

  writeU16(response + 4, 1);   // QDCOUNT
  writeU16(response + 6, 0);   // ANCOUNT
  writeU16(response + 8, 0);   // NSCOUNT
  writeU16(response + 10, 0);  // ARCOUNT

  int outLen = qEnd;
  if (qclass == 1 && (qtype == 1 || qtype == 28)) {
    const uint16_t rdlen = (qtype == 1) ? 4 : 16;
    if ((size_t)outLen + 12 + rdlen > DNS_BUF) return;

    response[outLen++] = 0xC0; response[outLen++] = 0x0C;  // QNAME pointer
    writeU16(response + outLen, qtype); outLen += 2;
    writeU16(response + outLen, 1); outLen += 2;  // IN
    response[outLen++] = (BLOCK_TTL >> 24) & 0xff;
    response[outLen++] = (BLOCK_TTL >> 16) & 0xff;
    response[outLen++] = (BLOCK_TTL >> 8) & 0xff;
    response[outLen++] = BLOCK_TTL & 0xff;
    writeU16(response + outLen, rdlen); outLen += 2;
    memset(response + outLen, 0, rdlen);
    outLen += rdlen;
    writeU16(response + 6, 1);  // ANCOUNT
  }
  sendDnsPacket(clientIP, clientPort, response, outLen);
}

int findPendingByUpstreamId(uint16_t id) {
  for (uint8_t i = 0; i < MAX_PENDING; i++) {
    if (pending[i].used && pending[i].upstreamId == id) return i;
  }
  return -1;
}

void expirePending() {
  uint32_t now = millis();
  for (uint8_t i = 0; i < MAX_PENDING; i++) {
    if (pending[i].used && (uint32_t)(now - pending[i].createdAt) > PENDING_TIMEOUT_MS) {
      pending[i].used = false;
      droppedQueries++;
    }
  }
}

int allocatePendingSlot() {
  for (uint8_t i = 0; i < MAX_PENDING; i++) {
    if (!pending[i].used) return i;
  }
  return -1;
}

uint16_t generateUniqueId() {
  for (uint8_t attempt = 0; attempt < 40; attempt++) {
    uint16_t id = (uint16_t)os_random();
    if (findPendingByUpstreamId(id) < 0) return id;
  }
  for (uint32_t id = 0; id <= 65535UL; id++) {
    if (findPendingByUpstreamId((uint16_t)id) < 0) return (uint16_t)id;
  }
  return 0;
}

void handleClientQuery(int len) {
  IPAddress clientIP = dnsSocket.remoteIP();
  uint16_t clientPort = dnsSocket.remotePort();

  if (len < 17 || len > (int)DNS_BUF) {
    malformedQueries++;
    return;
  }
  if (packet[2] & 0x80) return;                // not a query
  if (((packet[2] >> 3) & 0x0f) != 0) return;  // standard QUERY only
  if (readU16(packet + 4) != 1) {
    malformedQueries++;
    return;
  }

  char domain[254];
  int nameEnd = parseQName(packet, len, 12, domain, sizeof(domain));
  if (nameEnd < 0 || nameEnd + 4 > len) {
    malformedQueries++;
    return;
  }

  uint16_t qtype = readU16(packet + nameEnd);
  uint16_t qclass = readU16(packet + nameEnd + 2);
  int qEnd = nameEnd + 4;

  totalQueries++;
  lastDomain = String(domain);

  bool localBlock = (qclass == 1 && isBlocked(domain));
  recordClient(clientIP, localBlock);
  if (localBlock) {
    blockedQueries++;
    rollBuckets();
    if (qtype == 1) bucketA[bucketHead]++;
    else if (qtype == 28) bucketAAAA[bucketHead]++;
    sendBlockedReply(qEnd, qtype, qclass, clientIP, clientPort);
    return;
  }

  // No uplink yet: nothing to forward to.
  if (WiFi.status() != WL_CONNECTED) {
    droppedQueries++;
    return;
  }

  int slot = allocatePendingSlot();
  if (slot < 0) {
    droppedQueries++;
    return;
  }

  uint16_t upstreamId = generateUniqueId();
  if (findPendingByUpstreamId(upstreamId) >= 0) {
    droppedQueries++;
    return;
  }

  pending[slot].used = true;
  pending[slot].clientId = readU16(packet);
  pending[slot].upstreamId = upstreamId;
  pending[slot].clientIP = clientIP;
  pending[slot].clientPort = clientPort;
  pending[slot].createdAt = millis();

  writeU16(packet, upstreamId);
  if (!upstreamSocket.beginPacket(UPSTREAM_DNS, 53)) {
    pending[slot].used = false;
    droppedQueries++;
    return;
  }
  upstreamSocket.write(packet, len);
  if (!upstreamSocket.endPacket()) {
    pending[slot].used = false;
    droppedQueries++;
    return;
  }
  forwardedQueries++;
}

void handleUpstreamReply(int len) {
  IPAddress sourceIP = upstreamSocket.remoteIP();
  uint16_t sourcePort = upstreamSocket.remotePort();

  if (len < 12 || len > (int)DNS_BUF) return;
  if (sourceIP != UPSTREAM_DNS || sourcePort != 53) return;
  if (!(response[2] & 0x80)) return;

  uint16_t id = readU16(response);
  int slot = findPendingByUpstreamId(id);
  if (slot < 0) return;

  writeU16(response, pending[slot].clientId);
  sendDnsPacket(pending[slot].clientIP, pending[slot].clientPort, response, len);
  pending[slot].used = false;
}

void pollDns() {
  expirePending();
  rollBuckets();

  for (uint8_t i = 0; i < 6; i++) {
    int n = dnsSocket.parsePacket();
    if (n <= 0) break;
    if (n > (int)DNS_BUF) {
      while (dnsSocket.available()) dnsSocket.read();
      malformedQueries++;
      continue;
    }
    int got = dnsSocket.read(packet, DNS_BUF);
    if (got > 0) handleClientQuery(got);
  }

  for (uint8_t i = 0; i < 6; i++) {
    int n = upstreamSocket.parsePacket();
    if (n <= 0) break;
    if (n > (int)DNS_BUF) {
      while (upstreamSocket.available()) upstreamSocket.read();
      continue;
    }
    int got = upstreamSocket.read(response, DNS_BUF);
    if (got > 0) handleUpstreamReply(got);
  }
}

// ---------- Web UI ----------
// Basic style: background #272C30, accent purple #5B4285 (matches the logo).
// Logo: inline SVG witch hat, shown beside the "Pender" heading.
#define LOGO_SVG \
  "<svg class='logo' viewBox='0 0 120 90' role='img' aria-label='Pender logo'>" \
  "<path d='M6 76C4 70 14 66 28 62C40 59 44 56 48 52C54 38 52 24 62 12C68 4 78 4 84 8C92 16 100 20 106 26C100 26 94 30 90 32C84 34 82 40 84 48C86 54 92 58 96 62C104 64 112 68 114 74C116 80 108 84 92 84C60 88 36 88 24 84C12 84 8 80 6 76Z' fill='#5B4285' stroke='#000' stroke-width='3.5' stroke-linejoin='round'/>" \
  "<path d='M46 54C56 50 76 52 92 58L94 66C80 70 58 70 44 64Z' fill='#000'/>" \
  "<rect x='50' y='52' width='20' height='20' rx='2' fill='#F79443' stroke='#000' stroke-width='3'/>" \
  "<rect x='55' y='57' width='10' height='10' rx='1' fill='#000'/>" \
  "<path d='M62 26L82 14M66 36L78 32' stroke='#000' stroke-width='3' stroke-linecap='round' fill='none'/>" \
  "</svg>"

// Browser tab / website icon: the same witch hat as an inline data-URI SVG
// (no extra route or image file needed, and it works before login).
#define FAVICON_LINK \
  "<link rel='icon' type='image/svg+xml' href=\"data:image/svg+xml," \
  "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 90'%3E" \
  "%3Cpath d='M6 76C4 70 14 66 28 62C40 59 44 56 48 52C54 38 52 24 62 12C68 4 78 4 84 8C92 16 100 20 106 26C100 26 94 30 90 32C84 34 82 40 84 48C86 54 92 58 96 62C104 64 112 68 114 74C116 80 108 84 92 84C60 88 36 88 24 84C12 84 8 80 6 76Z' fill='%235B4285' stroke='%23000' stroke-width='5' stroke-linejoin='round'/%3E" \
  "%3Cpath d='M46 54C56 50 76 52 92 58L94 66C80 70 58 70 44 64Z' fill='%23000'/%3E" \
  "%3Crect x='50' y='52' width='20' height='20' rx='2' fill='%23F79443' stroke='%23000' stroke-width='4'/%3E" \
  "%3Crect x='55' y='57' width='10' height='10' rx='1' fill='%23000'/%3E" \
  "%3C/svg%3E\">"

static const char CSS[] PROGMEM =
  ":root{--bg:#272C30;--accent:#5B4285;--accent-text:#a590cf;--ink:#e8ebed;--muted:#a3adb4;--line:#3c444a;--panel:#2e3438}"
  "*{box-sizing:border-box}"
  "body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Arial,Helvetica,sans-serif}"
  ".wrap{max-width:900px;margin:0 auto;padding:20px 14px}"
  "header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:16px}"
  "h1{font-size:22px;margin:0;display:flex;align-items:center;gap:10px}h2{font-size:16px;margin:0 0 10px;color:var(--accent-text)}"
  ".logo{width:44px;height:auto;flex:none}"
  "a{color:var(--accent-text)}p{margin:0 0 10px}"
  ".grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}"
  ".box{background:var(--panel);border:1px solid var(--line);padding:12px;margin-bottom:14px}"
  ".grid .box{margin:0}"
  ".n{font-size:26px;font-weight:bold}.m{color:var(--muted);font-size:13px}"
  "table{width:100%;border-collapse:collapse}"
  "th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:13px}th{color:var(--muted)}"
  "label{font-size:13px;color:var(--muted)}"
  "input[type=text],input[type=password],input[type=time],input[type=number]{width:100%;padding:9px;background:var(--bg);color:var(--ink);border:1px solid var(--line);margin:4px 0 12px;font-size:15px}"
  "button,.btn{background:var(--accent);color:#fff;border:1px solid var(--accent);padding:9px 16px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block}"
  ".alt{background:transparent;color:var(--accent-text);border-color:var(--accent)}"
  ".kv{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}"
  ".k{font-size:12px;color:var(--muted)}.v{word-break:break-word}"
  ".leg span{display:inline-block;width:10px;height:10px;margin:0 5px 0 0}.leg{margin-top:6px}"
  ".leg i{display:inline-block;margin-right:16px;font-style:normal}"
  "@media(max-width:640px){.grid{grid-template-columns:repeat(2,1fr)}.kv{grid-template-columns:1fr}}";

void out(const String& s) { web.sendContent(s); }

void sendHead(const char* title, bool refresh) {
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "text/html; charset=utf-8", "");
  String s;
  s.reserve(2400);
  s += F("<!doctype html><html><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>");
  s += F(FAVICON_LINK);
  s += F("<title>");
  s += title;
  s += F("</title><style>");
  s += FPSTR(CSS);
  s += F("</style></head><body><main class='wrap'>");
  out(s);
}

void sendFoot() {
  out(String("</main></body></html>"));
  out(String(""));  // ends the chunked response
}

String esc(const String& in) {
  String o;
  o.reserve(in.length() + 8);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '&': o += F("&amp;"); break;
      case '<': o += F("&lt;"); break;
      case '>': o += F("&gt;"); break;
      case '"': o += F("&quot;"); break;
      case '\'': o += F("&#39;"); break;
      default: o += c;
    }
  }
  return o;
}

String uplinkText() {
  if (WiFi.status() == WL_CONNECTED) {
    String t = F("Connected to ");
    t += esc(WiFi.SSID());
    t += F(" (");
    t += WiFi.localIP().toString();
    t += F(")");
    return t;
  }
  if (hasCreds()) {
    String t = F("Not connected. Trying ");
    t += esc(String(cfg.ssid));
    return t;
  }
  return String(F("No network saved"));
}

String uptimeText() {
  uint32_t sec = millis() / 1000UL;
  uint32_t d = sec / 86400UL, h = (sec % 86400UL) / 3600UL, m = (sec % 3600UL) / 60UL;
  String t;
  if (d) { t += String(d); t += F("d "); }
  t += String(h); t += F("h ");
  t += String(m); t += F("m");
  return t;
}

// Stacked bar chart, drawn server-side as inline SVG (no scripts, works offline).
// Green body = IPv4 (A) lookups blocked, purple head = IPv6 (AAAA) lookups blocked.
void sendChart() {
  const int W = 600, H = 210, L = 34, R = 6, T = 10, B = 26;
  const int PW = W - L - R, PH = H - T - B;
  const int slot = PW / BUCKETS;
  const int barW = 14;
  const int base = T + PH;

  uint16_t maxV = 4;
  for (uint8_t i = 0; i < BUCKETS; i++) {
    uint16_t sum = bucketA[i] + bucketAAAA[i];
    if (sum > maxV) maxV = sum;
  }

  String s;
  s.reserve(2600);
  s += F("<svg viewBox='0 0 600 210' width='100%' role='img' aria-label='Blocked DNS lookups per 5 minutes'>");

  for (int g = 0; g <= 2; g++) {
    int y = base - (PH * g / 2);
    s += F("<line x1='34' x2='594' y1='");
    s += String(y);
    s += F("' y2='");
    s += String(y);
    s += F("' stroke='#3c444a'/>");
    s += F("<text x='30' y='");
    s += String(y + 3);
    s += F("' text-anchor='end' font-size='10' fill='#a3adb4'>");
    s += String((uint32_t)maxV * g / 2);
    s += F("</text>");
  }

  for (uint8_t i = 0; i < BUCKETS; i++) {
    uint8_t idx = (bucketHead + 1 + i) % BUCKETS;
    uint16_t a = bucketA[idx], p = bucketAAAA[idx];
    int hg = (int)((uint32_t)a * PH / maxV);
    int hp = (int)((uint32_t)p * PH / maxV);
    if (a > 0 && hg < 2) hg = 2;
    if (p > 0 && hp < 3) hp = 3;
    if (hg + hp > PH) hg = PH - hp;
    int x = L + i * slot + (slot - barW) / 2;

    if (hg > 0) {
      s += F("<rect x='");
      s += String(x);
      s += F("' y='");
      s += String(base - hg);
      s += F("' width='14' height='");
      s += String(hg);
      s += F("' fill='#3fb55d'/>");
    }
    if (hp > 0) {
      s += F("<rect x='");
      s += String(x);
      s += F("' y='");
      s += String(base - hg - hp);
      s += F("' width='14' height='");
      s += String(hp);
      s += F("' fill='#9b5de5'/>");
    }

    s += F("<text x='");
    s += String(x + barW / 2);
    s += F("' y='");
    s += String(H - 9);
    s += F("' text-anchor='middle' font-size='10' fill='#a3adb4'>");
    if (i == BUCKETS - 1) s += F("now");
    else { s += F("-"); s += String((BUCKETS - 1 - i) * 5); s += F("m"); }
    s += F("</text>");
  }
  s += F("</svg>");
  out(s);
}

// Protect every web route with a browser login prompt.
bool requireSiteLogin() {
  // First-use mode: allow the dashboard/settings until a password is chosen.
  if (siteAuth.pass[0] == '\0') return true;
  if (web.authenticate(siteAuth.user, siteAuth.pass)) return true;
  web.requestAuthentication(BASIC_AUTH, "Pender site", "Login required");
  return false;
}

void handleDashboard() {
  if (!requireSiteLogin()) return;
  rollBuckets();
  uint32_t now = millis();
  uint32_t pct = totalQueries ? (blockedQueries * 100UL / totalQueries) : 0;
  uint8_t activeClients = 0;
  for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].used && (uint32_t)(now - clients[i].lastSeen) < 300000UL) activeClients++;
  }

  // ?live=1 is the background refresh: send only the changing sections
  // (no head, CSS, logo, favicon or script), which is much lighter and
  // lets the page update without reloading.
  bool live = web.hasArg("live");
  if (live) {
    web.setContentLength(CONTENT_LENGTH_UNKNOWN);
    web.sendHeader("Cache-Control", "no-store");
    web.send(200, "text/html; charset=utf-8", "");
  } else {
    sendHead("Pender", true);
  }

  String s;
  s.reserve(1800);
  if (!live) {
    s += F("<header><h1>" LOGO_SVG "Pender</h1><nav><a class='btn alt' href='/wifi'>Wi-Fi setup</a> <a class='btn alt' href='/settings'>Password settings</a> <a class='btn alt' href='/restart'>Restart configuration</a></nav></header>"
           "<div id='live'>");
  }
  s += F("<section class='grid'><div class='box'><div class='m'>DNS requests</div><div class='n'>");
  s += String(totalQueries);
  s += F("</div></div><div class='box'><div class='m'>Blocked locally</div><div class='n'>");
  s += String(blockedQueries);
  s += F("</div><div class='m'>");
  s += String(pct);
  s += F("% of requests</div></div><div class='box'><div class='m'>Devices seen</div><div class='n'>");
  s += String(activeClients);
  s += F("</div><div class='m'>last 5 min</div></div><div class='box'><div class='m'>Forwarded</div><div class='n'>");
  s += String(forwardedQueries);
  s += F("</div><div class='m'>to AdGuard DNS</div></div></section>");
  s += F("<section class='box'><h2>Blocked lookups, last hour</h2>");
  out(s);

  sendChart();

  s = F("<div class='leg m'><i><span style='background:#3fb55d'></span>IPv4 (A) blocked</i>"
        "<i><span style='background:#9b5de5'></span>IPv6 (AAAA) blocked</i></div>"
        "<div class='m'>Each bar is 5 minutes. Counts only cover the local blocklist.</div></section>");
  s += F("<section class='box'><h2>Connected DNS clients</h2><table><thead><tr><th>Device IP</th><th>Requests</th><th>Blocked</th><th>Last seen</th></tr></thead><tbody>");
  bool any = false;
  for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
    if (!clients[i].used) continue;
    any = true;
    uint32_t age = (uint32_t)(now - clients[i].lastSeen) / 1000UL;
    s += F("<tr><td>");
    s += clients[i].ip.toString();
    s += F("</td><td>");
    s += String(clients[i].queries);
    s += F("</td><td>");
    s += String(clients[i].blocked);
    s += F("</td><td>");
    if (age < 60) { s += String(age); s += F(" sec ago"); }
    else { s += String(age / 60); s += F(" min ago"); }
    s += F("</td></tr>");
  }
  if (!any) s += F("<tr><td colspan='4'>No DNS clients yet. Join the pender network and browse a website.</td></tr>");
  s += F("</tbody></table></section>");
  out(s);

  s = F("<section class='box'><h2>Status</h2><div class='kv'><div><div class='k'>Network hosted</div><div class='v'>");
  s += esc(String(AP_SSID));
  s += F(" (");
  s += WiFi.softAPIP().toString();
  s += F(")</div></div><div><div class='k'>Devices on pender</div><div class='v'>");
  s += String(WiFi.softAPgetStationNum());
  s += F("</div></div><div><div class='k'>Uplink Wi-Fi</div><div class='v'>");
  s += uplinkText();
  s += F("</div></div><div><div class='k'>Home-network website</div><div class='v'>");
  if (WiFi.status() == WL_CONNECTED) {
    s += F("http://");
    s += WiFi.localIP().toString();
    s += F(" <span class='m'>(IP assigned automatically by your router)</span>");
  } else {
    s += F("Connect to your home Wi-Fi in Wi-Fi setup first");
  }
  s += F("</div></div><div><div class='k'>Upstream resolver</div><div class='v'>AdGuard DNS ");
  s += UPSTREAM_DNS.toString();
  s += F("</div></div><div><div class='k'>Last requested domain</div><div class='v'>");
  s += esc(lastDomain);
  s += F("</div></div><div><div class='k'>Dropped / malformed</div><div class='v'>");
  s += String(droppedQueries);
  s += F(" / ");
  s += String(malformedQueries);
  s += F("</div></div><div><div class='k'>Free memory</div><div class='v'>");
  s += String(ESP.getFreeHeap());
  s += F(" bytes</div></div><div><div class='k'>Uptime</div><div class='v'>");
  s += uptimeText();
  s += F("</div></div></div>"
         "<p class='m' style='margin-top:12px'>Requests filtered by AdGuard upstream show as forwarded, since this proxy cannot see that decision. "
         "Dashboard updates automatically every 3 seconds. <span class='live-note'>Live updates enabled</span></p></section>");
  out(s);

  if (live) {
    out(String(""));  // ends the chunked response
    return;
  }

  // Refresh only the #live block in the background. Requests are chained
  // (next one starts after the previous finishes) so they never pile up,
  // and the DOM is updated on the next animation frame to avoid jank.
  out(F("</div><script>"
        "(()=>{const el=document.getElementById('live');"
        "const tick=async()=>{if(!document.hidden){"
        "const ac=new AbortController(),to=setTimeout(()=>ac.abort(),5000);"
        "try{const r=await fetch('/?live=1',{cache:'no-store',signal:ac.signal});"
        "if(r.ok){const t=await r.text();"
        "requestAnimationFrame(()=>{el.innerHTML=t;"
        "const n=el.querySelector('.live-note');if(n)n.textContent='Live - updated '+new Date().toLocaleTimeString();});}}"
        "catch(e){}finally{clearTimeout(to);}}"
        "setTimeout(tick,3000);};"
        "setTimeout(tick,3000);})();"
        "</script>"));

  sendFoot();
}

// The Wi-Fi pages only work for devices joined to "pender".
bool fromAP() {
  if (web.client().localIP() == WiFi.softAPIP()) return true;
  web.send(403, "text/plain", "Open this page from the pender network.");
  return false;
}

void handleWifiPage() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  sendHead("Wi-Fi setup", false);

  String s;
  s.reserve(1800);
  s += F("<header><h1>Wi-Fi setup</h1><a class='btn alt' href='/'>Dashboard</a></header>"
         "<section class='box'><h2>Current uplink</h2><p>");
  s += uplinkText();
  s += F("</p></section><section class='box'><h2>Connect to a Wi-Fi network</h2>"
         "<form method='POST' action='/wifi/save'>"
         "<label for='ssid'>Network name (SSID)</label>"
         "<input type='text' id='ssid' name='ssid' maxlength='32' autocomplete='off' value='");
  s += esc(String(cfg.ssid));
  s += F("' required>"
         "<label for='pass'>Password (leave empty for an open network)</label>"
         "<input type='password' id='pass' name='pass' maxlength='63' autocomplete='off'>"
         "<button type='submit'>Save and connect</button></form></section>");
  if (hasCreds()) {
    s += F("<section class='box'><h2>Saved network</h2>"
           "<form method='POST' action='/wifi/forget'><button class='alt' type='submit'>Forget saved network</button></form></section>");
  }
  s += F("<p class='m'>Connecting can take about 15 seconds. The pender network may drop for a moment while the radio switches channel; "
         "if that happens, rejoin pender and reload this page.</p>");
  out(s);
  sendFoot();
}

void sendMessagePage(int code, const char* title, const String& body,
                     const char* href = "/wifi", const char* label = "Back to Wi-Fi setup");

void handleSettingsPage() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  sendHead("Password settings", false);
  String s = F("<header><h1>Password settings</h1><a class='btn alt' href='/'>Dashboard</a></header>"
               "<section class='box'><h2>Change website login</h2>"
               "<p class='m'>Choose a username and a new password. The change is saved on the ESP8266 and survives restart.</p>"
               "<form method='POST' action='/settings/save'>"
               "<label for='user'>New username</label><input type='text' id='user' name='user' maxlength='32' autocomplete='username' required value='");
  s += esc(String(siteAuth.user));
  s += F("'><label for='pass'>New password (8–63 characters)</label>"
         "<input id='pass' name='pass' type='password' minlength='8' maxlength='63' autocomplete='new-password' required>"
         "<label for='confirm'>Confirm new password</label>"
         "<input id='confirm' name='confirm' type='password' minlength='8' maxlength='63' autocomplete='new-password' required>"
         "<button type='submit'>Save login details</button></form></section>"
         "<p class='m'>After saving, your browser may keep the old login cached. Close and reopen the browser tab, then sign in with the new details.</p>");
  out(s);
  sendFoot();
}

void handleSettingsSave() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  String user = web.arg("user");
  String pass = web.arg("pass");
  String confirm = web.arg("confirm");
  if (user.length() < 1 || user.length() > 32) {
    sendMessagePage(400, "Not saved", String(F("Username must be 1 to 32 characters.")));
    return;
  }
  if (pass.length() < 8 || pass.length() > 63) {
    sendMessagePage(400, "Not saved", String(F("Password must be 8 to 63 characters.")));
    return;
  }
  if (pass != confirm) {
    sendMessagePage(400, "Not saved", String(F("The passwords do not match. Go back and try again.")));
    return;
  }
  saveSiteAuth(user, pass);
  sendMessagePage(200, "Login saved", String(F("Your website login has been saved. Close this tab, open http://192.168.4.1 again, and sign in with your new username and password.")));
}

void handleRestartPage() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  sendHead("Restart", false);

  char hhmm[6];
  snprintf(hhmm, sizeof(hhmm), "%02u:%02u", rcfg.hour, rcfg.minute);

  String s;
  s.reserve(2200);
  s += F("<header><h1>Restart</h1><a class='btn alt' href='/'>Dashboard</a></header>"
         "<section class='box'><h2>Scheduled daily restart</h2>"
         "<p class='m'>Restarting once a day clears memory so the device does not crash after running for a long time. "
         "The time comes from the internet, so it needs the uplink Wi-Fi to be connected.</p>"
         "<form method='POST' action='/restart/save'>"
         "<label><input type='checkbox' name='on' value='1'");
  if (rcfg.enabled) s += F(" checked");
  s += F("> Restart automatically every day</label><br><br>"
         "<label for='time'>Restart time (24-hour)</label>"
         "<input type='time' id='time' name='time' required value='");
  s += hhmm;
  s += F("'><label for='tz'>Your timezone, hours from UTC</label>"
         "<input type='number' id='tz' name='tz' min='-12' max='14' step='0.5' required value='");
  s += String(rcfg.tzHalfHrs / 2.0f, 1);
  s += F("'><button type='submit'>Save schedule</button></form></section>");

  s += F("<section class='box'><h2>Status</h2><div class='kv'><div><div class='k'>Schedule</div><div class='v'>");
  if (rcfg.enabled) { s += F("Daily at "); s += hhmm; }
  else s += F("Off");
  s += F("</div></div><div><div class='k'>Clock</div><div class='v'>");
  if (clockSynced()) {
    time_t t = time(nullptr);
    struct tm* lt = localtime(&t);
    char now[12];
    snprintf(now, sizeof(now), "%02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);
    s += now;
  } else {
    s += F("Waiting for internet time");
  }
  s += F("</div></div><div><div class='k'>Uptime</div><div class='v'>");
  s += uptimeText();
  s += F("</div></div></div></section>");

  s += F("<section class='box'><h2>Restart now</h2>"
         "<p class='m'>Restarts the device immediately. The pender network drops for about 10 seconds.</p>"
         "<form method='POST' action='/restart/now'><button class='alt' type='submit'>Restart now</button></form></section>");
  out(s);
  sendFoot();
}

void handleRestartSave() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  String t = web.arg("time");
  if (t.length() != 5 || t[2] != ':' || !isDigit(t[0]) || !isDigit(t[1]) ||
      !isDigit(t[3]) || !isDigit(t[4])) {
    sendMessagePage(400, "Not saved", String(F("Please pick a valid restart time.")), "/restart", "Back to Restart");
    return;
  }
  int hh = t.substring(0, 2).toInt();
  int mm = t.substring(3, 5).toInt();
  if (hh > 23 || mm > 59) {
    sendMessagePage(400, "Not saved", String(F("Please pick a valid restart time.")), "/restart", "Back to Restart");
    return;
  }
  float tz = web.arg("tz").toFloat();
  if (tz < -12.0f) tz = -12.0f;
  if (tz > 14.0f) tz = 14.0f;

  rcfg.enabled = web.hasArg("on") ? 1 : 0;
  rcfg.hour = (uint8_t)hh;
  rcfg.minute = (uint8_t)mm;
  rcfg.tzHalfHrs = (int8_t)lroundf(tz * 2.0f);
  saveRestartCfg();
  startClock();  // apply the new timezone

  String body = rcfg.enabled ? String(F("Saved. The device will restart every day at ")) + t + F(".")
                             : String(F("Saved. Scheduled restart is off."));
  if (rcfg.enabled && !clockSynced()) {
    body += F(" The clock is still waiting for internet time, so the schedule starts once the uplink Wi-Fi is connected.");
  }
  sendMessagePage(200, "Saved", body, "/restart", "Back to Restart");
}

void handleRestartNow() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  restartNowPending = true;
  restartNowAt = millis() + 1500;  // let this page finish sending first
  sendMessagePage(200, "Restarting", String(F("The device is restarting. Rejoin the pender network in about 10 seconds, then reopen the dashboard.")),
                  "/", "Dashboard");
}

// Fires the daily restart. The 2-minute uptime guard stops a restart loop:
// after rebooting inside the target minute the clock could still match.
void checkScheduledRestart() {
  static uint32_t lastCheck = 0;
  if (restartNowPending && (int32_t)(millis() - restartNowAt) >= 0) ESP.restart();
  if (!rcfg.enabled) return;
  if ((uint32_t)(millis() - lastCheck) < 5000UL) return;
  lastCheck = millis();
  if (millis() < 120000UL) return;
  if (!clockSynced()) return;
  time_t t = time(nullptr);
  struct tm* lt = localtime(&t);
  if (lt->tm_hour == rcfg.hour && lt->tm_min == rcfg.minute) ESP.restart();
}

void sendMessagePage(int code, const char* title, const String& body, const char* href, const char* label) {
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(code, "text/html; charset=utf-8", "");
  String s;
  s.reserve(2400);
  s += F("<!doctype html><html><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>");
  s += F(FAVICON_LINK);
  s += F("<title>");
  s += title;
  s += F("</title><style>");
  s += FPSTR(CSS);
  s += F("</style></head><body><main class='wrap'><header><h1>");
  s += title;
  s += F("</h1></header><section class='box'><p>");
  s += body;
  s += F("</p><a class='btn' href='");
  s += href;
  s += F("'>");
  s += label;
  s += F("</a></section></main></body></html>");
  out(s);
  out(String(""));
}

void handleWifiSave() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  String ssid = web.arg("ssid");
  String pass = web.arg("pass");

  if (ssid.length() < 1 || ssid.length() > 32) {
    sendMessagePage(400, "Not saved", String(F("The network name must be 1 to 32 characters.")));
    return;
  }
  if (pass.length() != 0 && (pass.length() < 8 || pass.length() > 63)) {
    sendMessagePage(400, "Not saved", String(F("The password must be 8 to 63 characters, or empty for an open network.")));
    return;
  }

  saveCfg(ssid, pass);
  connectRequested = true;  // connect from loop(), after this response is sent

  String body = F("Saved. Connecting to ");
  body += esc(ssid);
  body += F(" now. Give it about 15 seconds, then check the status on the Wi-Fi setup page.");
  sendMessagePage(200, "Saved", body);
}

void handleWifiForget() {
  if (!requireSiteLogin()) return;
  if (!fromAP()) return;
  clearCfg();
  WiFi.disconnect();
  web.sendHeader("Location", "/wifi");
  web.send(303, "text/plain", "");
}

void startAccessPoint() {
  WiFi.softAPConfig(AP_IP, AP_IP, AP_MASK);
  if (strlen(AP_PASS) >= 8) WiFi.softAP(AP_SSID, AP_PASS);
  else WiFi.softAP(AP_SSID);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nESP8266 DNS Ad Blocker - pender edition");

  for (uint8_t i = 0; i < MAX_PENDING; i++) pending[i].used = false;
  bucketStart = millis();

  system_update_cpu_freq(SYS_CPU_160MHZ);  // faster page rendering and DNS handling
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  startAccessPoint();

  loadCfg();
  startClock();
  if (hasCreds()) {
    // Do not call WiFi.config() with a fixed address: ESP8266 uses DHCP,
    // so the home router automatically assigns its LAN IP address.
    WiFi.begin(cfg.ssid, cfg.pass);
    lastAttempt = millis();
  }

#if ENABLE_NAPT
  naptInit = (ip_napt_init(512, 10) == ERR_OK);
#endif

  if (!dnsSocket.begin(DNS_PORT)) {
    Serial.println("Could not start client DNS socket on port 53.");
    delay(1000);
    ESP.restart();
  }
  if (!upstreamSocket.begin(0)) {
    Serial.println("Could not start upstream UDP socket.");
    delay(1000);
    ESP.restart();
  }

  web.on("/favicon.ico", HTTP_GET, []() { web.send(204); });  // icon comes from the <link> tag
  web.on("/", HTTP_GET, handleDashboard);
  web.on("/wifi", HTTP_GET, handleWifiPage);
  web.on("/settings", HTTP_GET, handleSettingsPage);
  web.on("/settings/save", HTTP_POST, handleSettingsSave);
  web.on("/restart", HTTP_GET, handleRestartPage);
  web.on("/restart/save", HTTP_POST, handleRestartSave);
  web.on("/restart/now", HTTP_POST, handleRestartNow);
  web.on("/wifi/save", HTTP_POST, handleWifiSave);
  web.on("/wifi/forget", HTTP_POST, handleWifiForget);
  web.onNotFound([]() { if (!requireSiteLogin()) return; web.send(404, "text/plain", "Not found"); });
  web.begin();

  Serial.print("Network: ");
  Serial.print(AP_SSID);
  Serial.print("  Dashboard: http://");
  Serial.println(WiFi.softAPIP());
}

void loop() {
  pollDns();
  web.handleClient();
  checkScheduledRestart();

  uint32_t now = millis();
  if (connectRequested) {
    connectRequested = false;
    delay(200);  // let the "Saved" page finish sending before the radio may change channel
    WiFi.disconnect();
    WiFi.begin(cfg.ssid, cfg.pass);
    lastAttempt = now;
  } else if (hasCreds() && WiFi.status() != WL_CONNECTED &&
             (uint32_t)(now - lastAttempt) > 20000UL) {
    lastAttempt = now;
    WiFi.begin(cfg.ssid, cfg.pass);
  }

#if ENABLE_NAPT
  if (naptInit && !naptOn && WiFi.status() == WL_CONNECTED) {
    ip_napt_enable_no(SOFTAP_IF, 1);
    naptOn = true;
  }
#endif

  yield();
}
