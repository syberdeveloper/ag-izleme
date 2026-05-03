# 🔐 Güvenlik Politikası

## Desteklenen Sürümler

| Sürüm | Destek Durumu |
|-------|---------------|
| 1.0.x | ✅ Aktif destek |

---

## 🐛 Güvenlik Açığı Bildirimi

Siber Kalkan'da bir güvenlik açığı keşfettiyseniz lütfen aşağıdaki adımları izleyin:

### ❌ Yapmamanız Gerekenler
- Güvenlik açığını GitHub Issues üzerinden **herkese açık olarak paylaşmayın**
- Sosyal medyada veya forumlarda açıklamayın

### ✅ Yapmanız Gerekenler

Güvenlik açıklarını doğrudan GitHub'ın **Private Vulnerability Reporting** özelliği üzerinden bildirin:

👉 [Güvenlik Açığı Bildir](https://github.com/syberdeveloper/ag-izleme/security/advisories/new)

Alternatif olarak GitHub profili üzerinden iletişime geçebilirsiniz.

---

## 📋 Bildiriminizde Şunları Belirtin

- Açığın türü (örn. bellek sızıntısı, JNI hatası, VPN tünel zafiyeti)
- Açığı tetiklemek için gereken adımlar
- Etkilenen dosya ve satır numaraları (varsa)
- Olası etkisi (veri sızıntısı, çökme, yetkisiz erişim vb.)

---

## ⏱️ Yanıt Süreci

| Aşama | Süre |
|-------|------|
| İlk yanıt | 48 saat içinde |
| Durum güncellemesi | 7 gün içinde |
| Düzeltme & yayın | 30 gün içinde (kritik açıklar için daha kısa) |

---

## 🛡️ Kapsam

Aşağıdaki bileşenler güvenlik bildirimi kapsamındadır:

- `lib.rs` — Rust DPI motoru ve JNI arayüzü
- `NetworkLogState.kt` — Tehdit analizi ve veri yönetimi
- `NetworkMonitorService.kt` — VPN servis katmanı
- `RustBridge.kt` — Kotlin–Rust köprüsü
- `AndroidManifest.xml` — İzin yapılandırması

---

## ✅ Teşekkür

Sorumlu güvenlik açığı bildirimi yapan araştırmacılar, istedikleri takdirde bu dosyada **Hall of Fame** bölümüne eklenecektir.

---

*Bu politika [GitHub Güvenlik Danışma Programı](https://docs.github.com/en/code-security/security-advisories) standartlarına uygundur.*