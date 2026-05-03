package com.example.agizleme

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap


//  VERİ MODELLERİ
data class PacketData(
    val timestampMillis: Long   = System.currentTimeMillis(),
    val time:          String,
    val appName:       String,
    val ip:            String,
    val host:          String,
    val effectiveHost: String,
    val tlsSni:        String,
    val httpHost:      String,
    val dnsQuery:      String,
    val port:          Int,
    val proto:         String,
    val isSuspicious:  Boolean,
    var threatScore:   Int,
    var anomalyType:   String,
    val size:          Int,
    val payload:       String,
    val ja3:           String,
    val isBeaconing:   Boolean,
    val isPortScan:    Boolean,
    val isNightExfil:  Boolean,
    var country:       String = "Sorgulanıyor...",
    var lat:           Double = 0.0,
    var lon:           Double = 0.0,
    var abuseScore:    Int    = -1,
    var isTorExit:     Boolean = false,
    var isKnownC2:     Boolean = false,
    var isBlocked:     Boolean = false,
    var isMalwareUrl:  Boolean = false
)

data class ThreatEvent(
    val timestamp:   Long,
    val ip:          String,
    val appName:     String,
    val anomalyType: String,
    val threatScore: Int,
    val details:     String
)

data class GeoCacheInfo(
    val text: String,
    val lat: Double,
    val lon: Double
)


//  ANA DURUM NESNESİ

object NetworkLogState {

    private val _allLogs         = MutableStateFlow<List<PacketData>>(emptyList())
    val allLogs: StateFlow<List<PacketData>> = _allLogs.asStateFlow()

    private val _suspiciousLogs  = MutableStateFlow<List<PacketData>>(emptyList())
    val suspiciousLogs: StateFlow<List<PacketData>> = _suspiciousLogs.asStateFlow()

    private val _blacklist       = MutableStateFlow<Set<String>>(emptySet())
    val blacklist: StateFlow<Set<String>> = _blacklist.asStateFlow()

    private val _appBandwidth    = MutableStateFlow<Map<String, Long>>(emptyMap())
    val appBandwidth: StateFlow<Map<String, Long>> = _appBandwidth.asStateFlow()

    private val _threatEvents    = MutableStateFlow<List<ThreatEvent>>(emptyList())
    val threatEvents: StateFlow<List<ThreatEvent>> = _threatEvents.asStateFlow()

    private val _threatIntelCache = MutableStateFlow<Map<String, ThreatIntelResult>>(emptyMap())
    val threatIntelCache: StateFlow<Map<String, ThreatIntelResult>> = _threatIntelCache.asStateFlow()

    // Cache güncellendi: Artık ülke metnini ve koordinatları tutuyor
    private val countryCache   = ConcurrentHashMap<String, GeoCacheInfo>()

    private val abuseCache     = ConcurrentHashMap<String, Int>()
    private val torExitNodes   = ConcurrentHashMap.newKeySet<String>()
    private val knownC2Ips     = ConcurrentHashMap.newKeySet<String>()
    private val malwareDomains = ConcurrentHashMap.newKeySet<String>()

    private val abuseApiCallTimes = ArrayDeque<Long>()
    private const val ABUSE_RATE_LIMIT = 30

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val RED_ZONES = setOf("RU", "CN", "IR", "KP", "SY", "CU")
    private const val SYSLOG_PORT = 514

    private var syslogServerIp = "192.168.1.100"
    private var abuseApiKey = ""

    fun updateConfig(syslogIp: String, apiKey: String) {
        syslogServerIp = syslogIp
        abuseApiKey = apiKey
    }

    private var pcapOutputStream: OutputStream? = null
    private var pcapPacketCount:  Long = 0L

    init {
        scope.launch { fetchTorExitNodes() }
        scope.launch { fetchFeodoC2List() }
        scope.launch { fetchUrlHausDomains() }
    }

    fun addLog(jsonString: String) {
        if (!jsonString.startsWith("{")) return
        try {
            val json = JSONObject(jsonString)
            val destIp    = json.getString("dest_ip")
            if (_blacklist.value.contains(destIp)) return

            val time          = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
            val srcIp         = json.getString("src_ip")
            val srcPort       = json.getInt("src_port")
            val destPort      = json.getInt("dest_port")
            val protoNum      = json.getInt("proto_num")
            val host          = json.getString("host")
            val effectiveHost = json.optString("effective_host", host)
            val tlsSni        = json.optString("tls_sni", "")
            val httpHost      = json.optString("http_host", "")
            val dnsQuery      = json.optString("dns_query", "")
            val size          = json.getInt("size")
            val payload       = json.optString("payload", "")
            val ja3           = json.optString("ja3", "")
            val proto         = json.getString("proto")

            val baseSuspicious= json.getBoolean("suspicious")
            var threatScore   = json.optInt("threat_score", 0)
            var anomalyType   = json.optString("anomaly_type", "NORMAL")

            val isBeaconing   = json.optBoolean("is_beaconing", false)
            val isPortScan    = json.optBoolean("is_port_scan", false)
            val isNightExfil  = json.optBoolean("is_night_exfil", false)

            val isTor = torExitNodes.contains(destIp)
            val isC2  = knownC2Ips.contains(destIp)
            val isMalwareUrl = malwareDomains.contains(effectiveHost) || (dnsQuery.isNotEmpty() && malwareDomains.contains(dnsQuery))

            val anomalyTags = anomalyType.split("|").filter { it.isNotEmpty() && it != "NORMAL" }.toMutableList()

            if (isTor) {
                threatScore += 100
                if (!anomalyTags.contains("TOR_EXIT")) anomalyTags.add("TOR_EXIT")
            }
            if (isC2) {
                threatScore += 100
                if (!anomalyTags.contains("BOTNET_C2")) anomalyTags.add("BOTNET_C2")
            }
            if (isMalwareUrl) {
                threatScore += 80
                if (!anomalyTags.contains("MALWARE_DOMAIN")) anomalyTags.add("MALWARE_DOMAIN")
            }
            if (baseSuspicious && effectiveHost.isEmpty() && proto == "TCP") {
                threatScore += 20
                if (!anomalyTags.contains("DIRECT_IP_ACCESS")) anomalyTags.add("DIRECT_IP_ACCESS")
            }

            val finalAnomalyType = if (anomalyTags.isEmpty()) "NORMAL" else anomalyTags.joinToString("|")
            val isSuspiciousFinal = baseSuspicious || isTor || isC2 || isMalwareUrl || threatScore >= 40

            val appName = resolveAppName(srcIp, srcPort, destIp, destPort, protoNum, effectiveHost)

            val bw = _appBandwidth.value.toMutableMap()
            bw[appName] = (bw[appName] ?: 0L) + size
            _appBandwidth.value = bw

            val isPrivate = isPrivateIp(destIp)

            // Eğer önceden sorduysak koordinatları çek, sormadıysak arkaplanda sor
            val cachedGeo = countryCache[destIp]
            val countryInfo = if (isPrivate) "🏠 Yerel Ağ" else (cachedGeo?.text ?: getOrFetchCountry(destIp))
            val packetLat = cachedGeo?.lat ?: 0.0
            val packetLon = cachedGeo?.lon ?: 0.0

            val packet = PacketData(
                timestampMillis = System.currentTimeMillis(),
                time          = time,
                appName       = appName,
                ip            = destIp,
                host          = host,
                effectiveHost = effectiveHost,
                tlsSni        = tlsSni,
                httpHost      = httpHost,
                dnsQuery      = dnsQuery,
                port          = destPort,
                proto         = proto,
                isSuspicious  = isSuspiciousFinal,
                threatScore   = threatScore.coerceAtMost(100),
                anomalyType   = finalAnomalyType,
                size          = size,
                payload       = payload,
                ja3           = ja3,
                isBeaconing   = isBeaconing,
                isPortScan    = isPortScan,
                isNightExfil  = isNightExfil,
                country       = countryInfo,
                lat           = packetLat,
                lon           = packetLon,
                isTorExit     = isTor,
                isKnownC2     = isC2,
                isMalwareUrl  = isMalwareUrl
            )

            appendLog(packet)

            if (packet.isSuspicious) {
                recordThreatEvent(packet)
                pushToSyslog(packet)
            }

            if (isTor || isC2 || isMalwareUrl) {
                addToBlacklist(destIp)
            }

            if (!isPrivate && threatScore > 20) {
                scope.launch { fetchAbuseScore(destIp) }
            }

        } catch (_: Exception) { }
    }

    private fun pushToSyslog(p: PacketData) {
        scope.launch {
            try {
                val timeMillis = System.currentTimeMillis()
                val priority = if (p.threatScore > 75) 10 else 14
                val msg = "<$priority>$timeMillis SiberKalkan: [THREAT] IP=${p.ip} APP=${p.appName} SCORE=${p.threatScore} ANOMALY=${p.anomalyType} DOMAIN=${p.effectiveHost} SNI=${p.tlsSni} JA3=${p.ja3}"
                val socket = DatagramSocket()
                val data = msg.toByteArray()
                val packet = DatagramPacket(data, data.size, InetAddress.getByName(syslogServerIp), SYSLOG_PORT)
                socket.send(packet)
                socket.close()
            } catch (_: Exception) { }
        }
    }

    private fun resolveAppName(
        srcIp: String, srcPort: Int, destIp: String, destPort: Int,
        protoNum: Int, host: String
    ): String {
        var name = "Bilinmeyen Uygulama"
        val ctx = RustBridge.appContext
        if (ctx != null) {
            try {
                val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val uid = cm.getConnectionOwnerUid(
                    protoNum,
                    InetSocketAddress(srcIp, srcPort),
                    InetSocketAddress(destIp, destPort)
                )
                if (uid != android.os.Process.INVALID_UID) {
                    val pm  = ctx.packageManager
                    val pkgs = pm.getPackagesForUid(uid)
                    if (!pkgs.isNullOrEmpty()) {
                        name = pm.getApplicationLabel(
                            pm.getApplicationInfo(pkgs[0], 0)
                        ).toString()
                    }
                }
            } catch (_: Exception) { }
        }
        return guessAppFromHost(host, name)
    }

    private fun guessAppFromHost(host: String, current: String): String {
        if (current != "Bilinmeyen Uygulama") return current
        val h = host.lowercase()
        return when {
            h.contains("whatsapp")                           -> "WhatsApp"
            h.contains("instagram") || h.contains("fbcdn")
                    || h.contains("facebook")                   -> "Instagram/Facebook"
            h.contains("youtube") || h.contains("googlevideo") -> "YouTube"
            h.contains("trendyol")                           -> "Trendyol"
            h.contains("spotify")                            -> "Spotify"
            h.contains("twitter") || h.contains("twimg")
                    || h.contains("scdn.co")                    -> "Twitter/X"
            h.contains("netflix")                            -> "Netflix"
            h.contains("1e100.net") || h.contains("googleapis") -> "Google Servisleri"
            h.contains("amazon") || h.contains("aws")        -> "Amazon/AWS"
            h.contains("apple") || h.contains("icloud")      -> "Apple Servisleri"
            h.contains("telegram")                           -> "Telegram"
            h.contains("discord")                            -> "Discord"
            h.contains("tiktok") || h.contains("byteoversea") -> "TikTok"
            else                                             -> "Bilinmeyen"
        }
    }

    private fun getOrFetchCountry(ip: String): String {
        countryCache[ip]?.let { return it.text }
        countryCache[ip] = GeoCacheInfo("Sorgulanıyor...", 0.0, 0.0)
        scope.launch {
            try {
                val url  = URL("https://ipwho.is/$ip")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    connectTimeout = 4000
                    readTimeout    = 4000
                    setRequestProperty("User-Agent", "Mozilla/5.0")
                }
                if (conn.responseCode == 200) {
                    val jsonText = conn.inputStream.bufferedReader().readText()
                    val json = JSONObject(jsonText)
                    if (json.optBoolean("success", false)) {
                        val country     = json.optString("country", "Bilinmiyor")
                        val countryCode = json.optString("country_code", "??").uppercase(Locale.ROOT)
                        val fetchedLat  = json.optDouble("latitude", 0.0)
                        val fetchedLon  = json.optDouble("longitude", 0.0)

                        val connectionObj = json.optJSONObject("connection")
                        val asn = connectionObj?.optInt("asn", 0)?.let { if (it > 0) "AS$it" else "" } ?: ""
                        val org = connectionObj?.optString("org", "") ?: ""

                        val flag = flagEmoji(countryCode)
                        val asnDetails = if (asn.isNotEmpty() || org.isNotEmpty()) {
                            val details = listOf(asn, org).filter { it.isNotEmpty() }.joinToString(" ")
                            " | $details"
                        } else ""

                        val result = "$flag $country$asnDetails"

                        countryCache[ip] = GeoCacheInfo(result, fetchedLat, fetchedLon)

                        if (RED_ZONES.contains(countryCode)) addToBlacklist(ip)

                        updateLogsWithCountry(ip, result, fetchedLat, fetchedLon)
                    }
                }
            } catch (_: Exception) { countryCache[ip] = GeoCacheInfo("🏴‍☠️ Hata", 0.0, 0.0) }
        }
        return "Sorgulanıyor..."
    }

    private fun flagEmoji(code: String): String {
        if (code.length != 2 || code == "??") return "🏴‍☠️"
        val a = Character.codePointAt(code, 0) - 0x41 + 0x1F1E6
        val b = Character.codePointAt(code, 1) - 0x41 + 0x1F1E6
        return String(Character.toChars(a)) + String(Character.toChars(b))
    }

    private fun updateLogsWithCountry(ip: String, country: String, lat: Double, lon: Double) {
        _allLogs.value       = _allLogs.value.map       { if (it.ip == ip) it.copy(country = country, lat = lat, lon = lon) else it }
        _suspiciousLogs.value = _suspiciousLogs.value.map { if (it.ip == ip) it.copy(country = country, lat = lat, lon = lon) else it }
    }

    data class ThreatIntelResult(
        val abuseScore: Int,
        val isTor:      Boolean,
        val isC2:       Boolean
    )

    private suspend fun fetchAbuseScore(ip: String) {
        if (abuseCache.containsKey(ip)) return
        val now = System.currentTimeMillis()
        synchronized(abuseApiCallTimes) {
            abuseApiCallTimes.removeAll { now - it > 60_000 }
            if (abuseApiCallTimes.size >= ABUSE_RATE_LIMIT) return
            abuseApiCallTimes.addLast(now)
        }
        try {
            val apiKey = abuseApiKey
            if (apiKey.isEmpty() || apiKey == "YOUR_ABUSEIPDB_API_KEY") return
            val url  = URL("https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 5000
                setRequestProperty("Key",    apiKey)
                setRequestProperty("Accept", "application/json")
            }
            if (conn.responseCode == 200) {
                val json  = JSONObject(conn.inputStream.bufferedReader().readText())
                val score = json.getJSONObject("data").optInt("abuseConfidenceScore", 0)
                abuseCache[ip] = score

                _allLogs.value = _allLogs.value.map { if (it.ip == ip) it.copy(abuseScore = score) else it }
                _suspiciousLogs.value = _suspiciousLogs.value.map { if (it.ip == ip) it.copy(abuseScore = score) else it }

                if (score >= 75) addToBlacklist(ip)

                val current = _threatIntelCache.value.toMutableMap()
                current[ip] = ThreatIntelResult(score, torExitNodes.contains(ip), knownC2Ips.contains(ip))
                _threatIntelCache.value = current
            }
        } catch (_: Exception) { }
    }

    private suspend fun fetchTorExitNodes() {
        try {
            val url  = URL("https://check.torproject.org/torbulkexitlist")
            val conn = (url.openConnection() as HttpURLConnection).apply { connectTimeout = 8000; readTimeout = 8000 }
            if (conn.responseCode == 200) {
                conn.inputStream.bufferedReader().forEachLine { line ->
                    val ip = line.trim()
                    if (ip.isNotEmpty() && !ip.startsWith("#")) torExitNodes.add(ip)
                }
            }
        } catch (_: Exception) { }
    }

    private suspend fun fetchFeodoC2List() {
        try {
            val url  = URL("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
            val conn = (url.openConnection() as HttpURLConnection).apply { connectTimeout = 8000; readTimeout = 8000 }
            if (conn.responseCode == 200) {
                conn.inputStream.bufferedReader().forEachLine { line ->
                    val ip = line.trim()
                    if (ip.isNotEmpty() && !ip.startsWith("#")) knownC2Ips.add(ip)
                }
            }
        } catch (_: Exception) { }
    }

    private suspend fun fetchUrlHausDomains() {
        try {
            val url = URL("https://urlhaus.abuse.ch/downloads/hostfile/")
            val conn = (url.openConnection() as HttpURLConnection).apply { connectTimeout = 8000; readTimeout = 8000 }
            if (conn.responseCode == 200) {
                conn.inputStream.bufferedReader().forEachLine { line ->
                    if (!line.startsWith("#") && line.isNotBlank()) {
                        val parts = line.split("\t")
                        if (parts.size >= 2) malwareDomains.add(parts[1].trim())
                    }
                }
            }
        } catch (_: Exception) { }
    }

    fun addToBlacklist(ip: String) {
        val updated = _blacklist.value + ip
        _blacklist.value = updated
        RustBridge.updateBlacklist(updated.joinToString(","))
    }

    fun removeFromBlacklist(ip: String) {
        val updated = _blacklist.value - ip
        _blacklist.value = updated
        RustBridge.updateBlacklist(updated.joinToString(","))
    }

    private fun recordThreatEvent(packet: PacketData) {
        val event = ThreatEvent(
            timestamp   = System.currentTimeMillis(),
            ip          = packet.ip,
            appName     = packet.appName,
            anomalyType = packet.anomalyType,
            threatScore = packet.threatScore,
            details     = buildEventDetails(packet)
        )
        val list = _threatEvents.value.toMutableList()
        list.add(0, event)
        if (list.size > 500) list.removeAt(list.lastIndex)
        _threatEvents.value = list
    }

    private fun buildEventDetails(p: PacketData): String {
        return buildString {
            if (p.effectiveHost.isNotEmpty()) append("DOMAIN=${p.effectiveHost} ")
            if (p.tlsSni.isNotEmpty())        append("SNI=${p.tlsSni} ")
            if (p.ja3.isNotEmpty())           append("JA3=${p.ja3} ")
            if (p.dnsQuery.isNotEmpty())      append("DNS=${p.dnsQuery} ")
            if (p.isTorExit)                  append("[TOR_EXIT] ")
            if (p.isKnownC2)                  append("[BOTNET_C2] ")
            if (p.isMalwareUrl)               append("[MALWARE_URL] ")
            if (p.isBeaconing)                append("[BEACON] ")
            if (p.isNightExfil)               append("[NIGHT_EXFIL] ")
            if (p.payload.isNotEmpty())       append("DATA=${p.payload.take(80)}")
        }.trim()
    }

    @SuppressLint("NewApi")
    private fun saveTextFileToDownloads(context: Context, fileName: String, mimeType: String, content: String): File {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val contentValues = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SiberKalkan")
            }
            val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
            if (uri != null) {
                context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(content) }
            }
            File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).absolutePath + "/SiberKalkan", fileName)
        } else {
            val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "SiberKalkan")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, fileName)
            file.writeText(content)
            file
        }
    }

    @SuppressLint("NewApi")
    fun startPcapCapture(context: Context) {
        try {
            val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            val fileName = "siber_kalkan_$ts.pcap"

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/vnd.tcpdump.pcap")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SiberKalkan")
                }
                val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                if (uri != null) {
                    pcapOutputStream = BufferedOutputStream(context.contentResolver.openOutputStream(uri))
                }
            } else {
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "SiberKalkan")
                if (!dir.exists()) dir.mkdirs()
                val file = File(dir, fileName)
                pcapOutputStream = BufferedOutputStream(FileOutputStream(file))
            }

            pcapOutputStream?.let {
                writePcapGlobalHeader(it)
                pcapPacketCount = 0L
            }
        } catch (_: Exception) { }
    }

    fun stopPcapCapture() {
        try { pcapOutputStream?.close() } catch (_: Exception) { }
        pcapOutputStream = null
    }

    fun writePcapPacket(rawPacket: ByteArray) {
        val out = pcapOutputStream ?: return
        try {
            val now    = System.currentTimeMillis()
            val tsSec  = (now / 1000).toInt()
            val tsUsec = ((now % 1000) * 1000).toInt()
            val len    = rawPacket.size

            val buf = ByteBuffer.allocate(16 + len).order(ByteOrder.LITTLE_ENDIAN)
            buf.putInt(tsSec)
            buf.putInt(tsUsec)
            buf.putInt(len)
            buf.putInt(len)
            buf.put(rawPacket)
            out.write(buf.array())
            out.flush()
            pcapPacketCount++
        } catch (_: Exception) { }
    }

    private fun writePcapGlobalHeader(out: OutputStream) {
        val buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0xA1B2C3D4.toInt())
        buf.putShort(2)
        buf.putShort(4)
        buf.putInt(0)
        buf.putInt(0)
        buf.putInt(65535)
        buf.putInt(101)
        out.write(buf.array())
    }

    fun generateIncidentReport(context: Context): File {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val fileName = "incident_report_${System.currentTimeMillis()}.md"

        val events = _threatEvents.value
        val topIps = _allLogs.value.groupBy { it.ip }.mapValues { it.value.size }
            .entries.sortedByDescending { it.value }.take(10)
        val topApps = _appBandwidth.value.entries.sortedByDescending { it.value }.take(10)

        val content = buildString {
            append("# \uD83D\uDEE1\uFE0F Siber Kalkan – Olay Raporu\n")
            append("**Oluşturulma:** $ts\n")
            append("**Toplam Paket:** ${_allLogs.value.size}\n")
            append("**Şüpheli Olay:** ${events.size}\n")
            append("**Kara Liste:** ${_blacklist.value.size} IP\n\n")
            append("## \uD83D\uDD34 Tehdit Olayları\n")
            events.take(50).forEach { e ->
                val t = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(e.timestamp))
                append("- [$t] **${e.ip}** (${e.appName}) — ${e.anomalyType} Score:${e.threatScore} — ${e.details}\n")
            }
            append("\n## \uD83D\uDCCA En Fazla Trafik Üreten IP'ler\n")
            topIps.forEach { (ip, count) ->
                val country = countryCache[ip]?.text ?: "?"
                append("- `$ip` $country — $count paket\n")
            }
            append("\n## \uD83D\uDCF1 Uygulama Bant Genişliği\n")
            topApps.forEach { (app, bytes) ->
                val mb = "%.2f MB".format(bytes / 1024.0 / 1024.0)
                append("- **$app**: $mb\n")
            }
            append("\n## \u26D4 Kara Liste\n")
            _blacklist.value.forEach { ip -> append("- `$ip`\n") }
        }

        return saveTextFileToDownloads(context, fileName, "text/markdown", content)
    }

    fun exportToJson(context: Context): File {
        val fileName = "siber_kalkan_export_${System.currentTimeMillis()}.json"
        val jsonArray = JSONArray()
        _allLogs.value.forEach { p ->
            val obj = JSONObject().apply {
                put("time", p.time)
                put("ip", p.ip)
                put("app", p.appName)
                put("threatScore", p.threatScore)
                put("anomaly", p.anomalyType)
                put("domain", p.effectiveHost)
                put("ja3", p.ja3)
                put("country_asn", p.country)
                put("latitude", p.lat)
                put("longitude", p.lon)
            }
            jsonArray.put(obj)
        }
        return saveTextFileToDownloads(context, fileName, "application/json", jsonArray.toString(4))
    }

    fun exportToCsv(context: Context): File {
        val fileName = "siber_kalkan_export_${System.currentTimeMillis()}.csv"
        val content = buildString {
            append("Time,IP,App,Score,Anomaly,Domain,JA3,Country_ASN,Lat,Lon\n")
            _allLogs.value.forEach { p ->
                append("${p.time},${p.ip},${p.appName},${p.threatScore},${p.anomalyType},${p.effectiveHost},${p.ja3},\"${p.country}\",${p.lat},${p.lon}\n")
            }
        }
        return saveTextFileToDownloads(context, fileName, "text/csv", content)
    }

    fun clearLogs() {
        _allLogs.value        = emptyList()
        _suspiciousLogs.value = emptyList()
        _appBandwidth.value   = emptyMap()
        _threatEvents.value   = emptyList()
    }

    private fun isPrivateIp(ip: String): Boolean =
        ip.startsWith("10.") || ip.startsWith("192.168.") ||
                ip.startsWith("172.16.") || ip.startsWith("127.") ||
                ip.startsWith("169.254.") || ip.startsWith("fd")

    private fun appendLog(packet: PacketData) {
        val all = _allLogs.value.toMutableList()
        all.add(0, packet)
        if (all.size > 2000) all.removeAt(all.lastIndex)
        _allLogs.value = all

        if (packet.isSuspicious) {
            val susp = _suspiciousLogs.value.toMutableList()
            susp.add(0, packet)
            if (susp.size > 1000) susp.removeAt(susp.lastIndex)
            _suspiciousLogs.value = susp
        }
    }
}