/*
 * Pengujian ECDH (P-256) pada ESP32-C6 - OUTPUT BAHASA MUDAH
 * Board  : ESP32-C6 (Arduino-ESP32 core 3.x)
 *
 * Yang diukur:
 *  1. Waktu eksekusi  : berapa lama pembuatan kunci & pembentukan kunci rahasia bersama
 *  2. Pemakaian RAM   : RAM tersisa sebelum, sesudah, dan titik terendah saat ECDH berjalan
 *  3. Penyimpanan     : ukuran program & file beban di flash
 *  4. Keberhasilan    : apakah kunci rahasia kedua pihak sama (32 byte = 256 bit)
 *  Kondisi uji dicatat: jenis Wi-Fi, kekuatan sinyal, ukuran file beban.
 *
 * File beban (FILE_SIZE_MB) hanya mengisi flash. ECDH tidak membaca file itu.
 *
 * PENGATURAN ARDUINO IDE (Tools):
 *   Flash Size       : 16MB
 *   Partition Scheme : 16M Flash (2MB APP/12.5MB FATFS)  <- nama bisa sedikit berbeda
 *   File beban dibuat otomatis oleh program di partisi FATFS (muat sampai sekitar 8 MB).
 */

#include <WiFi.h>
#include <FFat.h>
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"

// ================== KONFIGURASI PENGUJIAN ==================
const bool  USE_WIFI   = true;            // false = Wi-Fi dimatikan (sesi pembanding)
const char* WIFI_LABEL = "WIFI_KAMPUS";   // WIFI_PRIBADI / WIFI_KAMPUS / TANPA_WIFI
const char* WIFI_SSID  = "HW-Mahasiswa";
const char* WIFI_PASS  = "";

const uint32_t FILE_SIZE_MB = 2;           // 0 (kosong), 2, 4, 8, 16
const int      N_RUNS       = 30;          // jumlah percobaan
// ===========================================================

static const char* DATA_FILE = "/beban.bin";

// ---------- Tipe data hasil (harus di atas semua fungsi agar lolos auto-prototype Arduino) ----------
struct Hasil {
  int64_t kgA, kgB, agA, agB;   // mikrodetik
  bool    sama;
};

static int rng_hw(void*, unsigned char* buf, size_t len) {
  esp_fill_random(buf, len);
  return 0;
}

// ---------- Pemantau RAM (mencatat titik terendah RAM tersisa) ----------
volatile uint32_t gMinFree = 0xFFFFFFFF;
volatile bool     gSampling = false;

void samplerTask(void*) {
  for (;;) {
    if (gSampling) {
      uint32_t f = esp_get_free_heap_size();
      if (f < gMinFree) gMinFree = f;
    }
    vTaskDelay(1);
  }
}

// ---------- Siapkan file beban di flash ----------
bool prepareLoad(uint32_t mb) {
  if (!FFat.begin(true)) {
    Serial.println("GAGAL: penyimpanan flash tidak bisa dibuka.");
    return false;
  }
  if (FFat.exists(DATA_FILE)) FFat.remove(DATA_FILE);   // hapus file hari sebelumnya
  if (mb == 0) return true;

  uint64_t target = (uint64_t)mb * 1024ULL * 1024ULL;
  uint64_t sisa   = FFat.totalBytes() - FFat.usedBytes();
  if (target > sisa) {
    Serial.printf("GAGAL: ruang flash tidak cukup. Diminta %lu MB, ruang tersedia hanya %.2f MB.\n",
                  (unsigned long)mb, sisa / 1048576.0);
    Serial.println("       Ganti Partition Scheme di Arduino IDE atau kecilkan ukuran file.");
    return false;
  }
  File f = FFat.open(DATA_FILE, FILE_WRITE);
  if (!f) { Serial.println("GAGAL: file beban tidak bisa dibuat."); return false; }

  static uint8_t blk[4096];
  esp_fill_random(blk, sizeof(blk));
  uint64_t written = 0;
  while (written < target) {
    size_t w = f.write(blk, sizeof(blk));
    if (w != sizeof(blk)) { Serial.println("GAGAL: penulisan file terhenti."); f.close(); return false; }
    written += w;
  }
  f.close();
  return true;
}

// ---------- Satu percobaan ECDH ----------
bool jalankanEcdh(Hasil& r) {
  mbedtls_ecp_group grp;
  mbedtls_mpi dA, dB, zA, zB;
  mbedtls_ecp_point QA, QB;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&dA); mbedtls_mpi_init(&dB);
  mbedtls_mpi_init(&zA); mbedtls_mpi_init(&zB);
  mbedtls_ecp_point_init(&QA); mbedtls_ecp_point_init(&QB);

  bool ok = false;
  int64_t t;

  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto selesai;

  t = esp_timer_get_time();
  if (mbedtls_ecdh_gen_public(&grp, &dA, &QA, rng_hw, NULL) != 0) goto selesai;
  r.kgA = esp_timer_get_time() - t;

  t = esp_timer_get_time();
  if (mbedtls_ecdh_gen_public(&grp, &dB, &QB, rng_hw, NULL) != 0) goto selesai;
  r.kgB = esp_timer_get_time() - t;

  t = esp_timer_get_time();
  if (mbedtls_ecdh_compute_shared(&grp, &zA, &QB, &dA, rng_hw, NULL) != 0) goto selesai;
  r.agA = esp_timer_get_time() - t;

  t = esp_timer_get_time();
  if (mbedtls_ecdh_compute_shared(&grp, &zB, &QA, &dB, rng_hw, NULL) != 0) goto selesai;
  r.agB = esp_timer_get_time() - t;

  r.sama = (mbedtls_mpi_cmp_mpi(&zA, &zB) == 0) && (mbedtls_mpi_size(&zA) == 32);
  ok = true;

selesai:
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&dA); mbedtls_mpi_free(&dB);
  mbedtls_mpi_free(&zA); mbedtls_mpi_free(&zB);
  mbedtls_ecp_point_free(&QA); mbedtls_ecp_point_free(&QB);
  return ok;
}

// ---------- Bantuan tampilan ----------
const char* artiSinyal(int rssi) {
  if (rssi == 0)    return "tidak terhubung";
  if (rssi >= -55)  return "sangat kuat";
  if (rssi >= -67)  return "baik";
  if (rssi >= -75)  return "cukup";
  return "lemah";
}

void garis() { Serial.println("------------------------------------------------------------"); }

void setup() {
  Serial.begin(115200);
  delay(1500);
  xTaskCreate(samplerTask, "sampler", 2048, NULL, 5, NULL);

  Serial.println();
  garis();
  Serial.println(" PENGUJIAN PEMBENTUKAN KUNCI ECDH PADA ESP32-C6");
  garis();

  // ----- 1. Jaringan -----
  bool terhubung = false;
  uint32_t waktuSambung = 0;
  int rssi = 0;
  if (USE_WIFI) {
    Serial.printf("Menyambungkan ke jaringan %s ...\n", WIFI_LABEL);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    uint32_t t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(100);
    terhubung = (WiFi.status() == WL_CONNECTED);
    waktuSambung = millis() - t0;
    rssi = terhubung ? WiFi.RSSI() : 0;
    if (terhubung) Serial.printf("Berhasil terhubung dalam %.2f detik.\n", waktuSambung / 1000.0);
    else           Serial.println("Tidak berhasil terhubung ke Wi-Fi (pengujian tetap dilanjutkan).");
  } else {
    WiFi.mode(WIFI_OFF);
    Serial.println("Wi-Fi dimatikan (sesi pembanding tanpa jaringan).");
  }

  // ----- 2. Beban flash -----
  Serial.printf("Menyiapkan file beban %lu MB di penyimpanan flash ...\n", (unsigned long)FILE_SIZE_MB);
  bool beban = prepareLoad(FILE_SIZE_MB);
  if (!beban) return;
  Serial.println("File beban siap (file ini hanya disimpan, tidak diolah oleh ECDH).");

  // ----- 3. Kondisi pengujian -----
  Serial.println();
  garis();
  Serial.println(" KONDISI PENGUJIAN");
  garis();
  Serial.printf("Jenis jaringan Wi-Fi           : %s\n", WIFI_LABEL);
  Serial.printf("Kekuatan sinyal                : %d dBm (%s)\n", rssi, artiSinyal(rssi));
  Serial.printf("Ukuran file beban di flash     : %lu MB\n", (unsigned long)FILE_SIZE_MB);
  Serial.printf("Total penyimpanan flash chip   : %u MB\n", (unsigned)(ESP.getFlashChipSize() / 1048576));
  Serial.printf("Ruang data terpakai            : %.2f MB dari %.2f MB\n",
                FFat.usedBytes() / 1048576.0, FFat.totalBytes() / 1048576.0);
  Serial.printf("Ukuran program (sketch)        : %.1f KB\n", ESP.getSketchSize() / 1024.0);
  Serial.printf("Jumlah percobaan               : %d kali\n", N_RUNS);

  // ----- 4. Pengukuran RAM (satu percobaan khusus) -----
  uint32_t ramSebelum = esp_get_free_heap_size();
  gMinFree = ramSebelum;
  gSampling = true;
  Hasil rRam = {};
  jalankanEcdh(rRam);
  gSampling = false;
  uint32_t ramSesudah = esp_get_free_heap_size();
  uint32_t ramTerendah = gMinFree;

  Serial.println();
  garis();
  Serial.println(" PEMAKAIAN RAM (memori kerja)");
  garis();
  Serial.printf("RAM yang tersisa SEBELUM ECDH jalan   : %u byte (%.1f KB)\n", ramSebelum, ramSebelum / 1024.0);
  Serial.printf("RAM yang tersisa SESUDAH ECDH selesai : %u byte (%.1f KB)\n", ramSesudah, ramSesudah / 1024.0);
  Serial.printf("RAM tersisa paling sedikit saat jalan : %u byte (%.1f KB)\n", ramTerendah, ramTerendah / 1024.0);
  Serial.printf("RAM yang dipakai ECDH saat puncak     : sekitar %u byte (%.1f KB)\n",
                ramSebelum - ramTerendah, (ramSebelum - ramTerendah) / 1024.0);
  Serial.println("(Sesudah selesai, RAM dikembalikan, jadi nilainya hampir sama seperti sebelumnya.)");
  Serial.println("(Nilai puncak adalah perkiraan karena dipantau tiap 1 milidetik.)");

  // ----- 5. Pengukuran waktu -----
  static int64_t kgA[100], kgB[100], agA[100], agB[100];
  int berhasil = 0;
  Serial.println();
  garis();
  Serial.println(" HASIL TIAP PERCOBAAN");
  garis();
  for (int i = 0; i < N_RUNS && i < 100; i++) {
    Hasil r = {};
    bool ok = jalankanEcdh(r);
    kgA[i] = r.kgA; kgB[i] = r.kgB; agA[i] = r.agA; agB[i] = r.agB;
    bool sukses = ok && r.sama;
    if (sukses) berhasil++;
    Serial.printf("Percobaan %2d: buat kunci Alice %.2f ms | buat kunci Bob %.2f ms | "
                  "bentuk kunci rahasia Alice %.2f ms | Bob %.2f ms | kunci rahasia kedua pihak %s\n",
                  i + 1, r.kgA / 1000.0, r.kgB / 1000.0, r.agA / 1000.0, r.agB / 1000.0,
                  sukses ? "SAMA (berhasil)" : "BEDA (gagal)");
    delay(200);
  }

  // ----- 6. Ringkasan -----
  int n = (N_RUNS < 100) ? N_RUNS : 100;
  double sKg = 0, sAg = 0, mn = 1e12, mx = 0;
  for (int i = 0; i < n; i++) {
    double total = (kgA[i] + kgB[i] + agA[i] + agB[i]) / 1000.0;
    sKg += (kgA[i] + kgB[i]) / 2000.0;
    sAg += (agA[i] + agB[i]) / 2000.0;
    if (total < mn) mn = total;
    if (total > mx) mx = total;
  }
  Serial.println();
  garis();
  Serial.println(" RINGKASAN (dalam bahasa sederhana)");
  garis();
  Serial.printf("Dari %d percobaan, %d berhasil membentuk kunci rahasia yang sama (%d bit / 32 byte).\n",
                n, berhasil, 256);
  Serial.printf("Rata-rata waktu membuat sepasang kunci : %.2f milidetik\n", sKg / n);
  Serial.printf("Rata-rata waktu membentuk kunci rahasia: %.2f milidetik\n", sAg / n);
  Serial.printf("Rata-rata total satu proses ECDH       : %.2f milidetik\n", (sKg + sAg) * 2 / n);
  Serial.printf("Proses ECDH tercepat / terlama         : %.2f / %.2f milidetik\n", mn, mx);
  Serial.printf("Kondisi: jaringan %s, sinyal %s, file beban %lu MB\n",
                WIFI_LABEL, artiSinyal(rssi), (unsigned long)FILE_SIZE_MB);

  // ----- 7. Data untuk Excel -----
  Serial.println();
  garis();
  Serial.println(" DATA UNTUK EXCEL (salin baris di bawah ini)");
  garis();
  Serial.println("jaringan,beban_mb,sinyal_dbm,percobaan,keygen_alice_ms,keygen_bob_ms,rahasia_alice_ms,rahasia_bob_ms");
  for (int i = 0; i < n; i++) {
    Serial.printf("%s,%lu,%d,%d,%.3f,%.3f,%.3f,%.3f\n",
                  WIFI_LABEL, (unsigned long)FILE_SIZE_MB, rssi, i + 1,
                  kgA[i] / 1000.0, kgB[i] / 1000.0, agA[i] / 1000.0, agB[i] / 1000.0);
  }
  Serial.println();
  Serial.println("SELESAI.");
}

void loop() {}
