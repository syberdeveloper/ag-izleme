use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::jint;
use std::os::fd::FromRawFd;
use std::fs::File;
use std::io::Read;
use std::thread;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::mem::ManuallyDrop;
use std::sync::Mutex;

use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use android_logger::Config;
use md5::{Md5, Digest};


//  KÜRESEL DURUM

/// Kotlin'den gelen kara liste
static BLACKLIST: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Bağlantı takip istatistikleri (beaconing / port scan tespiti)
struct ConnectionTracker {
    /// IP başına son N paketin zamanı  (beaconing tespiti)
    packet_times:        HashMap<String, VecDeque<Instant>>,
    /// IP başına hedef port seti       (port tarama tespiti)
    scanned_ports:       HashMap<String, HashSet<u16>>,
    /// Uygulama başına yüklenen byte   (veri sızdırma tespiti)
    upload_bytes:        HashMap<String, u64>,
    /// Uygulama başına yükleme zamanı  (gece aktivitesi)
    upload_timestamps:   HashMap<String, Vec<u64>>,
    /// Beacon aralığı tespiti: IP → son iki paket arası ms listesi
    beacon_intervals:    HashMap<String, VecDeque<u64>>,
    /// ICMP Tünelleme takibi için IP bazlı payload boyutları
    icmp_payload_sizes:  HashMap<String, u64>,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            packet_times:       HashMap::new(),
            scanned_ports:      HashMap::new(),
            upload_bytes:       HashMap::new(),
            upload_timestamps:  HashMap::new(),
            beacon_intervals:   HashMap::new(),
            icmp_payload_sizes: HashMap::new(),
        }
    }

    /// Son 10 saniyede 20'den fazla farklı porta gidilmişse port tarama
    fn is_port_scanning(&self, src_ip: &str) -> bool {
        self.scanned_ports
            .get(src_ip)
            .map(|s| s.len() > 20)
            .unwrap_or(false)
    }

    /// Paketler arası aralık ≤ %10 sapmayla düzenliyse beacon
    fn is_beaconing(&self, dest_ip: &str) -> bool {
        let intervals = match self.beacon_intervals.get(dest_ip) {
            Some(v) if v.len() >= 5 => v,
            _ => return false,
        };
        let mean = intervals.iter().sum::<u64>() / intervals.len() as u64;
        if mean == 0 { return false; }
        let variance = intervals.iter()
            .map(|&x| { let d = x as i64 - mean as i64; (d * d) as u64 })
            .sum::<u64>() / intervals.len() as u64;
        let std_dev = (variance as f64).sqrt();
        std_dev / (mean as f64) < 0.10   // %10 eşiği
    }

    /// Gece 00:00–06:00 arasında 10 MB üzeri yükleme → şüpheli
    fn is_night_exfiltration(&self, app: &str) -> bool {
        let bytes = self.upload_bytes.get(app).copied().unwrap_or(0);
        if bytes < 10 * 1024 * 1024 { return false; }
        self.upload_timestamps.get(app).map(|ts| {
            ts.iter().any(|&t| {
                let secs_in_day = t % 86400;
                secs_in_day < 6 * 3600   // 00:00 – 06:00 UTC
            })
        }).unwrap_or(false)
    }

    /// 5KB üzeri ICMP payload'ı şüphelidir (Data Exfiltration over Ping)
    fn is_icmp_tunneling(&self, src_ip: &str) -> bool {
        self.icmp_payload_sizes.get(src_ip).copied().unwrap_or(0) > 5000
    }

    /// Yeni paket kaydı
    fn record_packet(&mut self, dest_ip: &str, dest_port: u16,
                     app: &str, size: usize, is_upload: bool, is_icmp: bool, src_ip: &str) {

        // ICMP Tünelleme kaydı
        if is_icmp {
            *self.icmp_payload_sizes.entry(src_ip.to_string()).or_insert(0) += size as u64;
        }

        // Port tarama kaydı (sadece 0 portundan farklıysa - ICMP portsuzdur)
        if dest_port != 0 {
            self.scanned_ports
                .entry(dest_ip.to_string())
                .or_default()
                .insert(dest_port);
        }

        // Paket zamanı (son 60 saniyeyi tut)
        let now = Instant::now();
        let times = self.packet_times
            .entry(dest_ip.to_string())
            .or_insert_with(VecDeque::new);
        times.push_back(now);
        while times.front().map(|t| now.duration_since(*t).as_secs() > 60).unwrap_or(false) {
            times.pop_front();
        }

        // Beacon aralığı kaydı
        if let Some(last) = times.iter().rev().nth(1) {
            let interval_ms = now.duration_since(*last).as_millis() as u64;
            let intervals = self.beacon_intervals
                .entry(dest_ip.to_string())
                .or_insert_with(VecDeque::new);
            intervals.push_back(interval_ms);
            if intervals.len() > 20 { intervals.pop_front(); }
        }

        // Bant genişliği & gece kaydı
        if is_upload {
            *self.upload_bytes.entry(app.to_string()).or_insert(0) += size as u64;
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.upload_timestamps
                .entry(app.to_string())
                .or_default()
                .push(ts);
        }
    }
}


//  JNI GİRİŞ NOKTALARI

/// Kotlin → Rust kara liste güncellemesi
#[no_mangle]
pub extern "system" fn Java_com_example_agizleme_RustBridge_updateBlacklist(
    mut env: JNIEnv,
    _class: JClass,
    ips: JString,
) {
    if let Ok(ip_str) = env.get_string(&ips) {
        let ip_string: String = ip_str.into();
        let mut list = BLACKLIST.lock().unwrap();
        *list = if ip_string.is_empty() {
            Vec::new()
        } else {
            ip_string.split(',').map(|s| s.trim().to_string()).collect()
        };
        log::debug!("Kara liste güncellendi: {} IP", list.len());
    }
}

/// VPN fd'si alınır, ayrı thread'de paket döngüsü başlar
#[no_mangle]
pub extern "system" fn Java_com_example_agizleme_RustBridge_startNativeMonitor(
    env: JNIEnv,
    _class: JClass,
    fd: jint,
    callback_obj: JObject,
) {
    android_logger::init_once(
        Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("VPN_RUST_CORE"),
    );

    let tun_file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    let callback_global = env.new_global_ref(callback_obj)
        .expect("Global ref alınamadı!");
    let jvm = env.get_java_vm().unwrap();

    thread::spawn(move || {
        packet_loop(tun_file, callback_global, jvm);
    });
}


//  PAKET DÖNGÜSÜ (IPv4 + IPv6 Mimarisi)

fn packet_loop(
    mut tun_file: ManuallyDrop<File>,
    callback_global: jni::objects::GlobalRef,
    jvm: jni::JavaVM,
) {
    let mut buffer = [0u8; 65535];
    let mut dns_cache: HashMap<IpAddr, String> = HashMap::new();
    let mut tracker = ConnectionTracker::new();
    let mut env = jvm.attach_current_thread().unwrap();

    loop {
        match tun_file.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let raw = &buffer[..n];
                if raw.is_empty() { continue; }

                let version = raw[0] >> 4;
                if version == 4 {
                    if let Some(ipv4) = Ipv4Packet::new(raw) {
                        process_ip_packet(
                            IpAddr::V4(ipv4.get_source()),
                            IpAddr::V4(ipv4.get_destination()),
                            ipv4.get_next_level_protocol(),
                            ipv4.payload(),
                            n, &mut dns_cache, &mut tracker, &mut env, &callback_global
                        );
                    }
                } else if version == 6 {
                    if let Some(ipv6) = Ipv6Packet::new(raw) {
                        process_ip_packet(
                            IpAddr::V6(ipv6.get_source()),
                            IpAddr::V6(ipv6.get_destination()),
                            ipv6.get_next_header(),
                            ipv6.payload(),
                            n, &mut dns_cache, &mut tracker, &mut env, &callback_global
                        );
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}


//  AĞ KATMANI İŞLEME (IPv4 & IPv6 Birleşik)

fn process_ip_packet(
    src_ip: IpAddr,
    dest_ip: IpAddr,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
    total_size: usize,
    dns_cache: &mut HashMap<IpAddr, String>,
    tracker: &mut ConnectionTracker,
    env: &mut JNIEnv,
    callback: &jni::objects::GlobalRef,
) {
    let mut src_port:      u16 = 0;
    let mut dest_port:     u16 = 0;
    let mut proto_name:    &str = "UNKNOWN";
    let mut proto_num:     u8  = 0;
    let mut is_icmp:       bool = false;
    let mut app_payload:   Vec<u8> = Vec::new();

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(payload) {
                src_port  = tcp.get_source();
                dest_port = tcp.get_destination();
                proto_name = "TCP";
                proto_num  = 6;
                let data = tcp.payload();
                let limit = std::cmp::min(data.len(), 512);
                app_payload.extend_from_slice(&data[..limit]);
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(payload) {
                src_port  = udp.get_source();
                dest_port = udp.get_destination();
                proto_name = "UDP";
                proto_num  = 17;
                let data = udp.payload();
                let limit = std::cmp::min(data.len(), 512);
                app_payload.extend_from_slice(&data[..limit]);
            }
        }
        IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
            proto_name = "ICMP";
            proto_num  = if protocol == IpNextHeaderProtocols::Icmp { 1 } else { 58 };
            is_icmp    = true;
            let limit = std::cmp::min(payload.len(), 512);
            app_payload.extend_from_slice(&payload[..limit]);
        }
        _ => return,
    }

    // ICMP paketlerinde port 0 olur, düşürme.
    if dest_port == 0 && !is_icmp { return; }

    let dest_ip_str = dest_ip.to_string();
    let src_ip_str  = src_ip.to_string();

    // --- Kara Liste Kontrolü ---
    {
        let list = BLACKLIST.lock().unwrap();
        if list.contains(&dest_ip_str) {
            log::debug!("Kara listedeki IP engellendi: {}", dest_ip_str);
            return;
        }
    }

    // --- DNS Arama ---
    let hostname = dns_cache.entry(dest_ip)
        .or_insert_with(|| {
            dns_lookup::lookup_addr(&dest_ip)
                .unwrap_or_else(|_| dest_ip_str.clone())
        })
        .clone();

    // --- Gelişmiş UDP/DNS Çözümleme (mDNS, DNS, QUIC, STUN) ---
    let dns_query = if proto_num == 17 && (dest_port == 53 || src_port == 53 || dest_port == 5353) {
        parse_dns_query(&app_payload)
    } else {
        None
    };

    let is_quic = proto_num == 17 && (dest_port == 443 || dest_port == 8443);
    let is_stun = proto_num == 17 && (dest_port == 3478 || dest_port == 5349);

    // --- TLS SNI (HTTPS domain tespiti) ---
    let tls_sni = if proto_num == 6 && dest_port == 443 {
        extract_tls_sni(&app_payload)
    } else {
        None
    };

    // --- HTTP Host Header ---
    let http_host = if proto_num == 6 && dest_port == 80 {
        extract_http_host(&app_payload)
    } else {
        None
    };

    // --- JA3 TLS Fingerprint Hash ---
    let ja3_hash = if proto_num == 6 && dest_port == 443 {
        extract_ja3_fingerprint(&app_payload)
    } else {
        String::new()
    };

    // --- Etkili Host (SNI > HTTP Host > DNS) ---
    let effective_host = tls_sni
        .clone()
        .or_else(|| http_host.clone())
        .or_else(|| dns_query.clone())
        .unwrap_or_else(|| hostname.clone());

    // --- Paket Kaydı & Anomali Tespiti ---
    let is_upload = src_ip_str.starts_with("10.") || src_ip_str.starts_with("192.168.") || src_ip_str.starts_with("172.16.") || src_ip_str.starts_with("fd");
    tracker.record_packet(&dest_ip_str, dest_port, &effective_host, total_size, is_upload, is_icmp, &src_ip_str);

    // --- Şüphelilik Kriterleri ---
    let suspicious_port = matches!(dest_port, 80 | 21 | 22 | 23 | 8080 | 8443 | 1080 | 4444 | 5555 | 6666 | 7777 | 9999);
    let is_beaconing    = tracker.is_beaconing(&dest_ip_str);
    let is_port_scan    = tracker.is_port_scanning(&src_ip_str);
    let is_night_exfil  = tracker.is_night_exfiltration(&effective_host);
    let is_icmp_tunnel  = tracker.is_icmp_tunneling(&src_ip_str);
    let has_clear_data  = suspicious_port && !app_payload.is_empty();

    let is_suspicious = suspicious_port || is_beaconing || is_port_scan || is_night_exfil || is_icmp_tunnel || is_quic || is_stun;

    // --- Anomali Türü ---
    let anomaly_type = build_anomaly_type(
        suspicious_port, is_beaconing, is_port_scan,
        is_night_exfil, is_icmp_tunnel, is_quic, is_stun,
        &tls_sni, &http_host, &dns_query,
    );

    // --- Payload Snippet (sadece şifresiz / şüpheli) ---
    let payload_snippet = if has_clear_data {
        sanitize_payload(&app_payload)
    } else {
        String::new()
    };

    // --- Tehdit Skoru (0-100) ---
    let threat_score = compute_threat_score(
        suspicious_port, is_beaconing, is_port_scan,
        is_night_exfil, is_icmp_tunnel, &tls_sni,
    );

    // --- JSON Mesajı ---
    let sni_str   = tls_sni.as_deref().unwrap_or("").replace('"', "\\\"");
    let host_str  = http_host.as_deref().unwrap_or("").replace('"', "\\\"");
    let dns_str   = dns_query.as_deref().unwrap_or("").replace('"', "\\\"");
    let eff_str   = effective_host.replace('"', "\\\"");
    let anomaly_e = anomaly_type.replace('"', "\\\"");
    let payload_e = payload_snippet.replace('"', "\\\"");
    let hostname_e = hostname.replace('"', "\\\"");
    let ja3_e      = ja3_hash.replace('"', "\\\"");

    let json_message = format!(
        r#"{{"src_ip":"{src_ip_str}","src_port":{src_port},"dest_ip":"{dest_ip_str}","dest_port":{dest_port},"proto":"{proto_name}","proto_num":{proto_num},"host":"{hostname_e}","effective_host":"{eff_str}","tls_sni":"{sni_str}","http_host":"{host_str}","dns_query":"{dns_str}","suspicious":{is_suspicious},"threat_score":{threat_score},"anomaly_type":"{anomaly_e}","size":{total_size},"payload":"{payload_e}","ja3":"{ja3_e}","is_beaconing":{is_beaconing},"is_port_scan":{is_port_scan},"is_night_exfil":{is_night_exfil}}}"#
    );

    // --- JNI Callback ---
    send_to_kotlin(env, callback, &json_message);
}


//  DERİN PAKET ANALİZİ (DPI) FONKSİYONLARI

/// DNS sorgu wire-format parse → ilk soru alanındaki domain
fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 { return None; }
    let flags = ((payload[2] as u16) << 8) | payload[3] as u16;
    if flags & 0x8000 != 0 { return None; }

    let mut i = 12usize;
    let mut domain = String::new();

    while i < payload.len() {
        let label_len = payload[i] as usize;
        if label_len == 0 { break; }
        if label_len & 0xC0 == 0xC0 { break; }
        i += 1;
        if i + label_len > payload.len() { return None; }
        if !domain.is_empty() { domain.push('.'); }
        domain.push_str(
            std::str::from_utf8(&payload[i..i + label_len]).ok()?
        );
        i += label_len;
    }

    if domain.is_empty() { None } else { Some(domain) }
}

/// TLS ClientHello'dan SNI extension'ını çıkar
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 6 { return None; }
    if payload[0] != 0x16 { return None; }
    if payload.len() < 6 || payload[5] != 0x01 { return None; }

    let mut offset = 5 + 4 + 2 + 32;

    if offset >= payload.len() { return None; }
    let session_id_len = payload[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > payload.len() { return None; }
    let cipher_len = u16::from_be_bytes([payload[offset], payload[offset+1]]) as usize;
    offset += 2 + cipher_len;

    if offset >= payload.len() { return None; }
    let comp_len = payload[offset] as usize;
    offset += 1 + comp_len;

    if offset + 2 > payload.len() { return None; }
    let ext_total = u16::from_be_bytes([payload[offset], payload[offset+1]]) as usize;
    offset += 2;

    let ext_end = std::cmp::min(offset + ext_total, payload.len());

    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset+1]]);
        let ext_len  = u16::from_be_bytes([payload[offset+2], payload[offset+3]]) as usize;
        offset += 4;
        if offset + ext_len > ext_end { break; }

        if ext_type == 0x0000 && ext_len >= 5 {
            let name_len = u16::from_be_bytes([payload[offset+3], payload[offset+4]]) as usize;
            let name_start = offset + 5;
            if name_start + name_len <= payload.len() {
                return std::str::from_utf8(&payload[name_start..name_start+name_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }
        offset += ext_len;
    }
    None
}

/// TLS JA3 Hash (Gerçek Algoritma)
/// Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats
fn extract_ja3_fingerprint(payload: &[u8]) -> String {
    // TLS Record Header: ContentType(1), Version(2), Length(2)
    if payload.len() < 6 { return String::new(); }
    if payload[0] != 0x16 { return String::new(); } // Handshake
    if payload[5] != 0x01 { return String::new(); } // ClientHello

    let mut offset = 5; // Record header'ı geç

    // Handshake Type (1), Length (3)
    offset += 4;
    if offset + 2 > payload.len() { return String::new(); }

    // TLS Version (ClientHello içindeki)
    let tls_version = u16::from_be_bytes([payload[offset], payload[offset+1]]);
    offset += 2;

    // Random (32)
    offset += 32;
    if offset >= payload.len() { return String::new(); }

    // Session ID
    let session_id_len = payload[offset] as usize;
    offset += 1 + session_id_len;
    if offset + 2 > payload.len() { return String::new(); }

    // Cipher Suites
    let cipher_len = u16::from_be_bytes([payload[offset], payload[offset+1]]) as usize;
    offset += 2;
    let mut ciphers = Vec::new();
    let cipher_end = offset + cipher_len;
    if cipher_end > payload.len() { return String::new(); }

    while offset + 2 <= cipher_end {
        let cipher = u16::from_be_bytes([payload[offset], payload[offset+1]]);
        // GREASE değerlerini yoksay (JA3 standartı)
        if (cipher & 0x0F0F) != 0x0A0A {
            ciphers.push(cipher.to_string());
        }
        offset += 2;
    }

    // Compression Methods
    if offset >= payload.len() { return String::new(); }
    let comp_len = payload[offset] as usize;
    offset += 1 + comp_len;
    if offset + 2 > payload.len() { return String::new(); }

    // Extensions
    let ext_total = u16::from_be_bytes([payload[offset], payload[offset+1]]) as usize;
    offset += 2;

    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    let ext_end = std::cmp::min(offset + ext_total, payload.len());

    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset+1]]);
        let ext_len  = u16::from_be_bytes([payload[offset+2], payload[offset+3]]) as usize;
        offset += 4;

        // GREASE değerlerini yoksay
        if (ext_type & 0x0F0F) != 0x0A0A {
            extensions.push(ext_type.to_string());
        }

        if offset + ext_len > ext_end { break; }

        // Supported Groups (Elliptic Curves) - Extension Type 10 (0x000a)
        if ext_type == 10 && ext_len >= 2 {
            let list_len = u16::from_be_bytes([payload[offset], payload[offset+1]]) as usize;
            let mut list_offset = offset + 2;
            let list_end = std::cmp::min(offset + ext_len, list_offset + list_len);

            while list_offset + 2 <= list_end {
                let curve = u16::from_be_bytes([payload[list_offset], payload[list_offset+1]]);
                if (curve & 0x0F0F) != 0x0A0A {
                    elliptic_curves.push(curve.to_string());
                }
                list_offset += 2;
            }
        }

        // EC Point Formats - Extension Type 11 (0x000b)
        if ext_type == 11 && ext_len >= 1 {
            let list_len = payload[offset] as usize;
            let mut list_offset = offset + 1;
            let list_end = std::cmp::min(offset + ext_len, list_offset + list_len);

            while list_offset < list_end {
                ec_point_formats.push(payload[list_offset].to_string());
                list_offset += 1;
            }
        }

        offset += ext_len;
    }

    // JA3 String Formatı: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats
    let ja3_string = format!(
        "{},{},{},{},{}",
        tls_version,
        ciphers.join("-"),
        extensions.join("-"),
        elliptic_curves.join("-"),
        ec_point_formats.join("-")
    );

    // Eğer geçerli bir ClientHello değilse veya veri yoksa boş dön
    if ciphers.is_empty() { return String::new(); }

    // MD5 Hash oluştur (Gerçek JA3 Fingerprint)
    let mut hasher = Md5::new();
    hasher.update(ja3_string.as_bytes());
    let result = hasher.finalize();

    format!("{:x}", result)
}

/// HTTP/1.x payload'ından Host: başlığını çıkar
fn extract_http_host(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            return Some(line[5..].trim().to_string());
        }
    }
    None
}


//  YARDIMCI FONKSİYONLAR

fn build_anomaly_type(
    suspicious_port: bool,
    beaconing: bool,
    port_scan: bool,
    night_exfil: bool,
    icmp_tunnel: bool,
    quic: bool,
    stun: bool,
    tls_sni: &Option<String>,
    http_host: &Option<String>,
    dns_query: &Option<String>,
) -> String {
    let mut tags: Vec<&str> = Vec::new();
    if suspicious_port { tags.push("CLEAR_CHANNEL"); }
    if beaconing       { tags.push("C2_BEACON"); }
    if port_scan       { tags.push("PORT_SCAN"); }
    if night_exfil     { tags.push("NIGHT_EXFIL"); }
    if icmp_tunnel     { tags.push("ICMP_TUNNEL"); }
    if quic            { tags.push("QUIC_DETECTED"); }
    if stun            { tags.push("STUN_WEBRTC"); }
    if tls_sni.is_some()  { tags.push("TLS_SNI"); }
    if http_host.is_some(){ tags.push("HTTP_HOST"); }
    if dns_query.is_some(){ tags.push("DNS_QUERY"); }
    if tags.is_empty() { "NORMAL".to_string() } else { tags.join("|") }
}

fn compute_threat_score(
    suspicious_port: bool,
    beaconing: bool,
    port_scan: bool,
    night_exfil: bool,
    icmp_tunnel: bool,
    tls_sni: &Option<String>,
) -> u8 {
    let mut score: u8 = 0;
    if suspicious_port { score = score.saturating_add(30); }
    if beaconing       { score = score.saturating_add(40); }
    if port_scan       { score = score.saturating_add(35); }
    if night_exfil     { score = score.saturating_add(25); }
    if icmp_tunnel     { score = score.saturating_add(50); }
    // TLS olmayan port 443'e gidiliyorsa düşük puanla
    if tls_sni.is_none() { score = score.saturating_add(5); }
    score.min(100)
}

fn sanitize_payload(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &b in data {
        match b {
            32..=126 => {
                match b as char {
                    '"'  => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c    => out.push(c),
                }
            }
            10 => out.push_str("\\n"),
            13 => {}
            _  => out.push('.'),
        }
        if out.len() >= 400 { break; }
    }
    out
}

fn send_to_kotlin(env: &mut JNIEnv, callback: &jni::objects::GlobalRef, msg: &str) {
    if let Ok(j_str) = env.new_string(msg) {
        let j_obj = JObject::from(j_str);
        let result = env.call_method(
            callback.as_obj(),
            "onNetworkDataReceived",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&j_obj)],
        );
        if result.is_err() { let _ = env.exception_clear(); }
        let _ = env.delete_local_ref(j_obj);
    }
}