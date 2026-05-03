# 🛡️ Siber Kalkan — Android Ağ İzleme & Tehdit Tespit Uygulaması

> **Paket:** `com.example.agizleme`  
> **Platform:** Android (min SDK 26 / API Q+ önerilir)  
> **Dil:** Kotlin + Rust (JNI üzerinden)  
> **UI:** Jetpack Compose + Material 3  
> **Mimari:** VPN tabanlı paket yakalama → Rust çekirdeği → Kotlin durum katmanı → Compose UI

---

## İçindekiler

1. [Proje Genel Bakış](#1-proje-genel-bakış)
2. [Mimari](#2-mimari)
3. [Modüller & Dosya Yapısı](#3-modüller--dosya-yapısı)
4. [Kurulum](#4-kurulum)
5. [Rust Çekirdeği Derleme](#5-rust-çekirdeği-derleme)
6. [Ekranlar & Özellikler](#6-ekranlar--özellikler)
7. [Tehdit Tespiti Algoritmaları](#7-tehdit-tespiti-algoritmaları)
8. [Tehdit İstihbaratı Kaynakları](#8-tehdit-istihbaratı-kaynakları)
9. [Dışa Aktarma & Raporlama](#9-dışa-aktarma--raporlama)
10. [API Anahtarları & Yapılandırma](#10-api-anahtarları--yapılandırma)
11. [Güvenlik & İzinler](#11-güvenlik--izinler)
12. [Veri Modelleri](#12-veri-modelleri)
13. [JNI / Rust–Kotlin İletişimi](#13-jni--rustkotlin-i̇letişimi)
14. [Bilinen Sınırlamalar](#14-bilinen-sınırlamalar)
15. [Katkı Rehberi](#15-katkı-rehberi)

---

## 1. Proje Genel Bakış

**Siber Kalkan**, Android cihazlarda çalışan, VPN tüneli aracılığıyla tüm ağ trafiğini gerçek zamanlı olarak izleyen, analiz eden ve tehdit skoru atayan bir siber güvenlik uygulamasıdır. Performans gerektiren derin paket incelemesi (DPI) için Rust tabanlı bir yerel kütüphane kullanılır; bu kütüphane JNI aracılığıyla Kotlin tarafıyla haberleşir.

### Temel Yetenekler

| Yetenek | Açıklama |
|---|---|
| VPN Tabanlı Yakalama | Tüm IPv4/IPv6 trafiğini root gerektirmeden yakalar |
| Derin Paket İncelemesi | TLS-SNI, HTTP Host, DNS, QUIC, STUN, ICMP tüneli tespiti |
| JA3 TLS Parmak İzi | Gerçek JA3 MD5 fingerprint algoritması (ClientHello parse) |
| Beacon Tespiti | İstatistiksel aralık analizi ile C2 işaret trafiği |
| Port Tarama Tespiti | 10 saniyede 20+ farklı porta erişim |
| Gece Sızdırma | 00:00–06:00 UTC arası 10 MB üzeri yükleme |
| ICMP Tünelleme | 5 KB üzeri ICMP payload tespiti |
| Canlı Tehdit İstihbaratı | TOR çıkış düğümleri, Feodo C2, URLHaus entegrasyonu |
| GeoIP & ASN | `ipwho.is` ile ülke, koordinat, ASN bilgisi |
| AbuseIPDB Entegrasyonu | IP itibar skoru (rate-limitli) |
| Kırmızı Bölge Bloğu | RU, CN, IR, KP, SY, CU kaynaklı IP'lerin otomatik engellenmesi |
| Firewall (Kara Liste) | Hem Kotlin hem Rust katmanında çift kademeli engelleme |
| PCAP Dışa Aktarma | Wireshark uyumlu `.pcap` dosyası |
| SIEM Entegrasyonu | JSON export + UDP Syslog (RFC 3164) |
| Harita Görünümü | OSMDroid üzerinde canlı tehdit haritası |

---

## 2. Mimari

```
┌─────────────────────────────────────────────────────────┐
│                    Jetpack Compose UI                    │
│  (MainActivity, 11 ekran, CyberTheme, ModalDrawer)       │
└───────────────────┬─────────────────────────────────────┘
                    │  StateFlow (Kotlin Coroutines)
┌───────────────────▼─────────────────────────────────────┐
│               NetworkLogState (Singleton)                │
│  • allLogs / suspiciousLogs / blacklist / appBandwidth   │
│  • threatEvents / threatIntelCache                       │
│  • GeoIP, AbuseIPDB, Syslog, PCAP, Export fonksiyonları │
└───────────────────┬─────────────────────────────────────┘
                    │  JNI (JSON string callback)
┌───────────────────▼─────────────────────────────────────┐
│                  RustBridge (object)                     │
│  • System.loadLibrary("agizleme")                        │
│  • startNativeMonitor(fd, callback)                      │
│  • updateBlacklist(ips)                                  │
└───────────────────┬─────────────────────────────────────┘
                    │  VPN tünel fd (ParcelFileDescriptor)
┌───────────────────▼─────────────────────────────────────┐
│              Rust Çekirdeği (lib.rs)                     │
│  • packet_loop → process_ip_packet                       │
│  • DPI: TLS-SNI, HTTP Host, DNS, JA3, QUIC, STUN        │
│  • ConnectionTracker: beaconing, port scan, exfil, ICMP  │
│  • BLACKLIST (Mutex<Vec<String>>)                        │
└───────────────────┬─────────────────────────────────────┘
                    │  Raw IPv4/IPv6 paketleri
┌───────────────────▼─────────────────────────────────────┐
│           NetworkMonitorService (VpnService)             │
│  • Foreground service + notification                     │
│  • VPN Builder: 10.0.0.2/32, route 0.0.0.0/0            │
│  • DNS: 8.8.8.8 | MTU: 1500                              │
└─────────────────────────────────────────────────────────┘
```

### Veri Akışı

```
Cihaz Trafiği
    → VPN Tüneli (fd)
        → Rust thread (packet_loop)
            → DPI Analizi
                → JSON string
                    → JNI: onNetworkDataReceived()
                        → NetworkLogState.addLog()
                            → Tehdit skorlama & enrichment
                                → StateFlow güncelleme
                                    → Compose UI yeniden çizim
```

---

## 3. Modüller & Dosya Yapısı

```
app/
└── src/main/
    ├── java/com/example/agizleme/
    │   ├── MainActivity.kt          # UI, tema, tüm Compose ekranları
    │   ├── NetworkMonitorService.kt # VpnService, foreground servis
    │   ├── NetworkLogState.kt       # Global durum, tehdit zenginleştirme
    │   └── RustBridge.kt           # JNI köprüsü
    └── jniLibs/                    # Derlenen .so dosyaları buraya
        ├── arm64-v8a/libagizleme.so
        ├── armeabi-v7a/libagizleme.so
        └── x86_64/libagizleme.so

rust_core/
├── Cargo.toml
└── src/
    └── lib.rs                      # Rust çekirdeği (DPI motoru)
```

---

### 3.1 `MainActivity.kt`

Uygulamanın tüm UI katmanını içerir.

**Tema Renkleri:**

| Sabit | Hex | Kullanım |
|---|---|---|
| `CyberBlack` | `#0A0A0A` | Arka plan |
| `MatrixGreen` | `#00FF41` | Birincil renk, metin |
| `DarkGray` | `#1A1A1A` | Kart yüzeyleri |
| `AlertRed` | `#FF003C` | Yüksek tehdit uyarısı |
| `WarnYellow` | `#FFD600` | Orta tehdit / şüpheli |
| `InfoBlue` | `#00B4FF` | Bilgi öğeleri |
| `PurpleC2` | `#BB00FF` | C2/botnet imleri |

**Navigasyon Ekranları (`DrawerScreen` enum):**

| Ekran | Terminal Kodu | Açıklama |
|---|---|---|
| `MAIN` | `> TERM_MAIN` | Canlı ağ trafiği akışı |
| `APP_DETECTION` | `> APP_DATA` | Uygulama & bant genişliği |
| `LOCATION` | `> GEO_IP` | Ülke & konum bilgileri |
| `THREAT_MAP` | `> THREAT_MAP` | OSMDroid canlı tehdit haritası |
| `SUSPICIOUS` | `> ANOMALY_DET` | Şüpheli trafik filtrelenmiş liste |
| `BLACKLIST` | `> FIREWALL` | IP kara liste yönetimi |
| `THREAT_INTEL` | `> THREAT_INTEL` | AbuseIPDB / TOR / C2 skorları |
| `THREAT_EVENTS` | `> EVENT_LOG` | Zaman damgalı olay günlüğü |
| `TRAFFIC_GRAPH` | `> TRAFFIC_GRAPH` | Gerçek zamanlı trafik grafiği |
| `DNS_LOG` | `> DNS_LOG` | Domain bazlı DNS sorgu günlüğü |
| `REPORT` | `> EXPORT` | Rapor oluşturma & dışa aktarma |

---

### 3.2 `NetworkMonitorService.kt`

`VpnService` sınıfından türetilmiş foreground servistir.

**VPN Yapılandırması:**

```text
builder.addAddress("10.0.0.2", 32)    // Sanal arayüz IP
builder.addRoute("0.0.0.0", 0)         // Tüm IPv4 trafiği tünel üzerinden
builder.addDnsServer("8.8.8.8")        // Google DNS
builder.setSession("Siber Kalkan")
builder.setMtu(1500)
builder.addDisallowedApplication(packageName) // Kendi uygulaması tünelden muaf
```

**Yaşam Döngüsü:**

```
onCreate() → createNotificationChannel()
onStartCommand(ACTION_START) → startVpn() → startForeground() + RustBridge.startNativeMonitor()
onStartCommand(ACTION_STOP)  → stopVpn()  → closeVpnInterface() + stopForeground()
onRevoke()  → closeVpnInterface()   // Kullanıcı izni iptal ederse
onDestroy() → closeVpnInterface()
```

---

### 3.3 `NetworkLogState.kt`

Uygulamanın merkezi durum ve iş mantığı katmanıdır. `object` (singleton) olarak tanımlanmıştır.

**StateFlow'lar:**

| Flow | Tip | Max Boyut | Açıklama |
|---|---|---|---|
| `allLogs` | `List<PacketData>` | 2000 | Tüm yakalanan paketler |
| `suspiciousLogs` | `List<PacketData>` | 1000 | Yalnızca şüpheli paketler |
| `blacklist` | `Set<String>` | — | Engellenen IP kümesi |
| `appBandwidth` | `Map<String, Long>` | — | Uygulama bazlı byte sayısı |
| `threatEvents` | `List<ThreatEvent>` | 500 | Tehdit olay günlüğü |
| `threatIntelCache` | `Map<String, ThreatIntelResult>` | — | IP başına istihbarat özeti |

**Başlangıçta Çekilen Listeler (init):**

```text
scope.launch { fetchTorExitNodes() }    // torproject.org/torbulkexitlist
scope.launch { fetchFeodoC2List() }     // feodotracker.abuse.ch
scope.launch { fetchUrlHausDomains() }  // urlhaus.abuse.ch/hostfile
```

**Otomatik Kara Listeye Ekleme Koşulları:**

- TOR çıkış düğümü olarak tespit edilirse
- Feodo C2 listesinde yer alıyorsa
- URLHaus kötü amaçlı domain listesinde ise
- GeoIP ülke kodu kırmızı bölgedeyse (`RU`, `CN`, `IR`, `KP`, `SY`, `CU`)
- AbuseIPDB skoru ≥ 75 ise

---

### 3.4 `RustBridge.kt`

Kotlin–Rust JNI köprüsüdür.

```text
object RustBridge {
    var appContext: Context? = null

    init { System.loadLibrary("agizleme") }   // libagizleme.so

    external fun startNativeMonitor(fd: Int, callback: RustBridge)
    external fun updateBlacklist(ips: String)  // Virgülle ayrılmış IP listesi

    // Rust → Kotlin geri çağırım (JNI üzerinden çağrılır)
    fun onNetworkDataReceived(message: String) {
        NetworkLogState.addLog(message)
    }
}
```

---

### 3.5 `lib.rs` — Rust Çekirdeği

**Cargo Bağımlılıkları:**

```text
[dependencies]
jni            = "0.21.1"   # JNI bağlamaları
pnet           = "0.34.0"   # Ham paket parse (IPv4/IPv6/TCP/UDP)
dns-lookup     = "2.0.4"    # Ters DNS çözümleme
android_logger = "0.13.0"   # Android Logcat entegrasyonu
log            = "0.4.20"   # log! makroları
serde          = "1.0"      # (Serileştirme altyapısı)
serde_json     = "1.0"      # JSON (ileride yapılandırma için)
md-5           = "0.10.6"   # JA3 fingerprint MD5 hash
```

---

## 4. Kurulum

### Ön Koşullar

- **Android Studio** Hedgehog veya üzeri
- **Android SDK** API 26+
- **NDK** (Rust derleme için)
- **Rust Toolchain** — [rustup.rs](https://rustup.rs) ile kurulur
- **cargo-ndk** — Android hedefleri için

### Adımlar

```text
# 1. Depoyu klonlayın
git clone https://github.com/kullanici/siber-kalkan.git
cd siber-kalkan

# 2. Rust toolchain hedeflerini ekleyin
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android

# 3. cargo-ndk yükleyin
cargo install cargo-ndk

# 4. Rust kütüphanesini derleyin (aşağıdaki bölüme bakın)

# 5. Android Studio'da projeyi açın
# File > Open > siber-kalkan/

# 6. Gradle Sync yapın
# Build > Make Project
```

---

## 5. Rust Çekirdeği Derleme

```text
cd rust_core/

# Tüm hedefler için derleme
cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o ../app/src/main/jniLibs \
  build --release
```

Başarılı derleme sonrası `.so` dosyaları otomatik olarak `jniLibs/` altına kopyalanır.

> **Not:** `ANDROID_NDK_HOME` ortam değişkeninin ayarlanmış olması gerekir.  
> Örnek: `export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/26.1.10909125`

**`build.gradle` (app) — NDK için gerekli yapılandırma:**

```text
android {
    defaultConfig {
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }
}
```

---

## 6. Ekranlar & Özellikler

### 6.1 Ana Ekran — Ağ İzleme (`MAIN`)

- Tüm yakalanan paketlerin canlı akışı
- Her satırda: zaman, uygulama adı, hedef IP, port, protokol, tehdit skoru
- Renk kodlaması: yeşil (normal), sarı (şüpheli), kırmızı (yüksek tehdit)
- VPN başlatma/durdurma kontrolü
- Aktif tehdit sayacı (drawer başlığında görünür)

### 6.2 Uygulama & Bant Genişliği (`APP_DETECTION`)

- `ConnectivityManager.getConnectionOwnerUid()` ile UID → paket adı çözümleme
- Domain bazlı uygulama tahmini (WhatsApp, Instagram, YouTube, Trendyol vb.)
- Uygulama başına toplam byte sayacı

### 6.3 Ülke & Konum (`LOCATION`)

- `ipwho.is` API ile GeoIP sorgusu (ülke, ülke kodu, ASN, organizasyon, enlem/boylam)
- Bayrak emoji gösterimi
- Kırmızı bölge (red zone) ülke tespiti ve otomatik engelleme

### 6.4 Tehdit Haritası (`THREAT_MAP`)

- **OSMDroid** ile OpenStreetMap üzerinde interaktif harita
- Her IP için koordinatlı marker (TOR → kırmızı, C2 → mor, diğer → sarı/yeşil)
- Gesture kontrolü: tehdit haritası aktifken drawer jesti devre dışı

### 6.5 Şüpheli Trafik (`SUSPICIOUS`)

- Yalnızca `isSuspicious = true` olan paketler listelenir
- Anomali etiketleri (TOR_EXIT, BOTNET_C2, C2_BEACON, PORT_SCAN vb.)
- Doğrudan kara listeye ekleme butonu

### 6.6 Firewall / Kara Liste (`BLACKLIST`)

- Mevcut kara listenin görüntülenmesi
- Manuel IP ekleme / silme
- Kara liste güncellendiğinde `RustBridge.updateBlacklist()` üzerinden Rust'a anlık iletim
- TXT olarak dışa aktarma

### 6.7 Tehdit İstihbaratı (`THREAT_INTEL`)

- AbuseIPDB skoru (0–100)
- TOR çıkış düğümü durumu
- Feodo C2 listesinde olup olmadığı
- Tehdit skoru görselleştirmesi

### 6.8 Olay Günlüğü (`THREAT_EVENTS`)

- Zaman damgalı tehdit olayları (max 500)
- IP, uygulama adı, anomali türü, tehdit skoru, detay
- UDP Syslog (RFC 3164) push entegrasyonu (öncelik 10 veya 14)

### 6.9 Trafik Grafiği (`TRAFFIC_GRAPH`)

- Zaman ekseninde paket sayısı / tehdit skoru grafiği
- Compose Canvas ile çizilmiş özel grafik

### 6.10 DNS Sorguları (`DNS_LOG`)

- Domain bazlı gruplandırılmış DNS sorguları
- Sorgu sayısı ve kaynak ülke bilgisi
- Şüpheli domain vurgulaması (sarı)

### 6.11 Rapor & Export (`REPORT`)

- Oturum istatistikleri (toplam paket, şüpheli, Tor, C2, beacon vb.)
- Beş farklı dışa aktarma formatı (bkz. Bölüm 9)

---

## 7. Tehdit Tespiti Algoritmaları

### 7.1 Beaconing (C2 İşaret Tespiti)

Bir IP adresine gönderilen son 20 paketin zaman aralıkları incelenir.  
Standart sapma / ortalama < **%10** ise trafik düzenli aralıklıdır → `C2_BEACON`.

```text
fn is_beaconing(&self, dest_ip: &str) -> bool {
    // Minimum 5 aralık gereklidir
    let mean = intervals.iter().sum::<u64>() / intervals.len() as u64;
    let variance = ...;
    let std_dev = (variance as f64).sqrt();
    std_dev / (mean as f64) < 0.10
}
```

### 7.2 Port Tarama Tespiti

Son 60 saniyede aynı kaynak IP'den **20'den fazla farklı hedef portuna** erişim → `PORT_SCAN`.

```text
fn is_port_scanning(&self, src_ip: &str) -> bool {
    self.scanned_ports.get(src_ip).map(|s| s.len() > 20).unwrap_or(false)
}
```

### 7.3 Gece Sızdırma Tespiti

Bir uygulama 10 MB'ı aşan veri yüklemişse ve bu yükleme **00:00–06:00 UTC** saatleri arasında gerçekleşmişse → `NIGHT_EXFIL`.

### 7.4 ICMP Tünelleme

Bir kaynak IP'den gelen toplam ICMP payload boyutu **5 KB'ı** aşıyorsa → `ICMP_TUNNEL`.

### 7.5 TLS JA3 Parmak İzi

Gerçek JA3 algoritması uygulanmıştır:

```
JA3 String = TLSVersion,Ciphersuites,Extensions,EllipticCurves,ECPointFormats
JA3 Hash   = MD5(JA3 String)
```

GREASE değerleri (`0x?A?A` deseni) JA3 standardına uygun şekilde filtrelenmektedir.

### 7.6 Tehdit Skoru Hesaplama (0–100)

| Faktör | Puan |
|---|---|
| Şüpheli port (21, 22, 23, 80, 1080, 4444…) | +30 |
| Beaconing tespiti | +40 |
| Port tarama | +35 |
| Gece sızdırma | +25 |
| ICMP tünelleme | +50 |
| TLS-SNI eksikliği (port 443) | +5 |
| TOR çıkış düğümü (Kotlin katmanı) | +100 |
| Bilinen C2 IP (Kotlin katmanı) | +100 |
| Kötü amaçlı domain (Kotlin katmanı) | +80 |
| Doğrudan IP erişimi, şifresiz TCP (Kotlin) | +20 |

Rust katmanı skoru **100** ile sınırlar; Kotlin katmanındaki eklemeler sonrası `coerceAtMost(100)` uygulanır.

---

## 8. Tehdit İstihbaratı Kaynakları

| Kaynak | URL | Güncelleme |
|---|---|---|
| TOR Çıkış Düğümleri | `https://check.torproject.org/torbulkexitlist` | Uygulama başlangıcında |
| Feodo C2 Listesi | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | Uygulama başlangıcında |
| URLHaus Kötü Amaçlı Domainler | `https://urlhaus.abuse.ch/downloads/hostfile/` | Uygulama başlangıcında |
| GeoIP & ASN | `https://ipwho.is/{ip}` | Her yeni IP için (önbellekli) |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/check` | Tehdit skoru > 20 olan IP'ler için (dakikada 30 istek sınırı) |

---

## 9. Dışa Aktarma & Raporlama

| Format | Dosya Adı | Konum |
|---|---|---|
| Markdown Olay Raporu | `incident_report_{ts}.md` | `Downloads/SiberKalkan/` |
| JSON (SIEM) | `siber_kalkan_export_{ts}.json` | `Downloads/SiberKalkan/` |
| CSV | `siber_kalkan_export_{ts}.csv` | `Downloads/SiberKalkan/` |
| Kara Liste TXT | `blacklist_{ts}.txt` | `Downloads/SiberKalkan/` |
| PCAP (Wireshark) | `siber_kalkan_{ts}.pcap` | `Downloads/SiberKalkan/` |

**PCAP Detayları:**  
Global header magic number `0xA1B2C3D4`, link-type `101` (RAW IP), little-endian formatında yazılır. Wireshark ve tcpdump ile doğrudan açılabilir.

**Syslog:**  
Şüpheli her olay `192.168.1.100:514` adresine UDP üzerinden RFC 3164 formatında gönderilir.  
Tehdit skoru > 75 → öncelik 10 (critical), diğerleri → 14 (informational).

> **Not:** Syslog sunucu adresini `NetworkLogState.kt` içindeki `SYSLOG_SERVER` sabitinden değiştirin.

---

## 10. API Anahtarları & Yapılandırma

### AbuseIPDB

`NetworkLogState.kt` içindeki `fetchAbuseScore()` fonksiyonunda:

```text
val apiKey = "YOUR_ABUSEIPDB_API_KEY"  // ← Buraya gerçek anahtarınızı yazın
```

API anahtarı girilmezse AbuseIPDB sorguları atlanır; diğer tüm tehdit istihbaratı özellikleri çalışmaya devam eder.

### Syslog Sunucu Adresi

```text
private const val SYSLOG_SERVER = "192.168.1.100"  // ← Kendi sunucunuz
private const val SYSLOG_PORT   = 514
```

### Kırmızı Bölge Ülkeleri

```text
private val RED_ZONES = setOf("RU", "CN", "IR", "KP", "SY", "CU")
```

---

## 11. Güvenlik & İzinler

### AndroidManifest.xml — Gerekli İzinler

```text
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
    android:maxSdkVersion="28" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
    android:maxSdkVersion="32" />

<service android:name=".NetworkMonitorService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

### Önemli Güvenlik Notları

- VPN izni kullanıcıdan `VpnService.prepare()` ile talep edilir; ret durumunda servis başlatılmaz.
- Kendi uygulaması (`packageName`) `addDisallowedApplication()` ile tünelden muaf tutulur; bu sayede GeoIP ve tehdit istihbaratı HTTP sorguları kesilmez.
- Rust katmanındaki `BLACKLIST` mutex korumalıdır; Kotlin ve Rust thread'leri eş zamanlı erişimi güvenlidir.

---

## 12. Veri Modelleri

### `PacketData`

```text
data class PacketData(
    val time: String,           // "HH:mm:ss"
    val appName: String,        // Uygulama adı veya "Bilinmeyen"
    val ip: String,             // Hedef IP
    val host: String,           // Ters DNS
    val effectiveHost: String,  // SNI > HTTP Host > DNS > host
    val tlsSni: String,         // TLS Server Name Indication
    val httpHost: String,       // HTTP Host header
    val dnsQuery: String,       // DNS sorgu domain
    val port: Int,              // Hedef port
    val proto: String,          // TCP / UDP / ICMP
    val isSuspicious: Boolean,
    var threatScore: Int,       // 0–100
    var anomalyType: String,    // "NORMAL" veya "TAG1|TAG2|..."
    val size: Int,              // Paket boyutu (byte)
    val payload: String,        // İlk 400 karakter (yalnızca şifresiz & şüpheli)
    val ja3: String,            // MD5 JA3 hash
    val isBeaconing: Boolean,
    val isPortScan: Boolean,
    val isNightExfil: Boolean,
    var country: String,        // "🇩🇪 Germany | AS1234 Deutsche Telekom"
    var lat: Double,
    var lon: Double,
    var abuseScore: Int,        // AbuseIPDB skoru (–1 = sorgulanmadı)
    var isTorExit: Boolean,
    var isKnownC2: Boolean,
    var isBlocked: Boolean,
    var isMalwareUrl: Boolean
)
```

### `ThreatEvent`

```text
data class ThreatEvent(
    val timestamp: Long,
    val ip: String,
    val appName: String,
    val anomalyType: String,
    val threatScore: Int,
    val details: String         // "DOMAIN=x SNI=y JA3=z [TOR_EXIT]"
)
```

### Anomali Etiketleri (Pipe-separated)

| Etiket | Kaynak | Açıklama |
|---|---|---|
| `CLEAR_CHANNEL` | Rust | Şifreli olmayan şüpheli port |
| `C2_BEACON` | Rust | Düzenli aralıklı iletişim |
| `PORT_SCAN` | Rust | Çok sayıda porta erişim |
| `NIGHT_EXFIL` | Rust | Gece saatlerinde büyük veri yükleme |
| `ICMP_TUNNEL` | Rust | ICMP üzerinden tünel |
| `QUIC_DETECTED` | Rust | UDP 443/8443 QUIC protokolü |
| `STUN_WEBRTC` | Rust | STUN/WebRTC (UDP 3478/5349) |
| `TLS_SNI` | Rust | TLS SNI çıkarıldı |
| `HTTP_HOST` | Rust | HTTP Host header çıkarıldı |
| `DNS_QUERY` | Rust | DNS sorgusu tespit edildi |
| `TOR_EXIT` | Kotlin | TOR çıkış düğümü |
| `BOTNET_C2` | Kotlin | Feodo C2 listesi eşleşmesi |
| `MALWARE_DOMAIN` | Kotlin | URLHaus domain eşleşmesi |
| `DIRECT_IP_ACCESS` | Kotlin | Domain olmadan doğrudan IP erişimi |

---

## 13. JNI / Rust–Kotlin İletişimi

### Kotlin → Rust

```text
// VPN monitörünü başlat
RustBridge.startNativeMonitor(fd: Int, callback: RustBridge)

// Kara listeyi güncelle (virgülle ayrılmış IP)
RustBridge.updateBlacklist("1.2.3.4,5.6.7.8")
```

**JNI Fonksiyon Adlandırması (Rust):**

```text
// Java_<paket_yolu_alt_çizgili>_<sınıf>_<metot>
#[no_mangle]
pub extern "system" fn Java_com_example_agizleme_RustBridge_startNativeMonitor(...)
pub extern "system" fn Java_com_example_agizleme_RustBridge_updateBlacklist(...)
```

### Rust → Kotlin (Callback)

Rust, JSON formatında bir string oluşturur ve JNI üzerinden `onNetworkDataReceived(String)` metodunu çağırır:

```text
fn send_to_kotlin(env: &mut JNIEnv, callback: &GlobalRef, msg: &str) {
    env.call_method(callback.as_obj(), "onNetworkDataReceived",
        "(Ljava/lang/String;)V", &[...]);
}
```

**Rust'tan gelen JSON şeması:**

```text
{
  "src_ip": "10.0.0.2",
  "src_port": 54321,
  "dest_ip": "1.2.3.4",
  "dest_port": 443,
  "proto": "TCP",
  "proto_num": 6,
  "host": "example.com",
  "effective_host": "api.example.com",
  "tls_sni": "api.example.com",
  "http_host": "",
  "dns_query": "",
  "suspicious": true,
  "threat_score": 40,
  "anomaly_type": "C2_BEACON|TLS_SNI",
  "size": 1024,
  "payload": "",
  "ja3": "abc123def456...",
  "is_beaconing": true,
  "is_port_scan": false,
  "is_night_exfil": false
}
```

---

## 14. Bilinen Sınırlamalar

| Sınırlama | Açıklama |
|---|---|
| IPv6 Yönlendirme | `addRoute("0.0.0.0", 0)` yalnızca IPv4'ü kapsar; IPv6 rotası ayrıca eklenmemiştir |
| `getConnectionOwnerUid()` | API 29+ gerektirir; eski sürümlerde uygulama adı çözümlenmez |
| AbuseIPDB Rate Limit | Dakikada 30 istek; ücretsiz planda günlük 1000 istek limiti vardır |
| GeoIP Doğruluğu | `ipwho.is` ücretsiz, VPN/proxy IP'lerinde doğruluk düşebilir |
| Syslog Sunucu | Varsayılan `192.168.1.100:514`; değiştirilmesi gerekir |
| PCAP Boyutu | Yoğun trafikte dosya boyutu hızla büyür; uzun süreli kayıtta dikkat edin |
| Uygulama Kendi Trafiği | `addDisallowedApplication` ile muaf tutulmuştur; istihbarat sorguları tünelden geçmez |
| Paket Tamponu (Rust) | Paket başına max 512 byte uygulama yükü okunur |

---

## 15. Katkı Rehberi

### Yeni Ekran Ekleme

1. `DrawerScreen` enum'una yeni bir değer ekleyin.
2. `MainActivity.kt` içindeki `when (currentScreen)` bloğuna yeni composable'ı ekleyin.
3. Drawer menüsüne otomatik olarak eklenir.

### Yeni Anomali Türü Ekleme

**Rust tarafında** (`lib.rs`):
1. `ConnectionTracker` struct'ına yeni alan ekleyin.
2. `record_packet()` içinde kaydı güncelleyin.
3. Tespit fonksiyonunu ekleyin (örn. `fn is_new_anomaly()`).
4. `build_anomaly_type()` ve `compute_threat_score()` içine yeni etiket ekleyin.

**Kotlin tarafında** (`NetworkLogState.kt`):
1. `addLog()` fonksiyonunda JSON'dan yeni alanı parse edin.
2. `PacketData` data class'ına alan ekleyin.
3. İlgili UI bileşeninde gösterimi güncelleyin.

### Kod Stili

- Kotlin: [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Rust: `rustfmt` varsayılan kuralları (`cargo fmt`)
- Türkçe yorum satırları korunmalıdır (proje dili)

---

## Lisans

Bu proje eğitim ve araştırma amaçlıdır. Üretim ortamında kullanım için ek güvenlik denetimleri önerilir.

---

*Son güncelleme: 2026 — Siber Kalkan Geliştirme Ekibi*