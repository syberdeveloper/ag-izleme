package com.example.agizleme

import android.app.Activity
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.ColorMatrix
import android.graphics.ColorMatrixColorFilter
import android.graphics.Paint
import android.annotation.SuppressLint
import android.graphics.Point
import android.graphics.drawable.BitmapDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.launch
import org.osmdroid.config.Configuration
import org.osmdroid.tileprovider.tilesource.TileSourceFactory
import org.osmdroid.util.GeoPoint
import org.osmdroid.views.MapView
import org.osmdroid.views.overlay.Marker
import org.osmdroid.views.overlay.Overlay
import java.io.File


//  TEMA RENKLERİ

val CyberBlack  = Color(0xFF0A0A0A)
val MatrixGreen = Color(0xFF00FF41)
val DarkGray    = Color(0xFF1A1A1A)
val MidGray     = Color(0xFF2A2A2A)
val AlertRed    = Color(0xFFFF003C)
val WarnYellow  = Color(0xFFFFD600)
val InfoBlue    = Color(0xFF00B4FF)
val PurpleC2    = Color(0xFFBB00FF)


//  NAVİGASYON EKRANLARI

enum class DrawerScreen(val title: String, val label: String) {
    MAIN          ("Ağ İzleme",              "> TERM_MAIN"),
    APP_DETECTION ("Uygulama & Bant Gen.",   "> APP_DATA"),
    LOCATION      ("Ülke & Konum",           "> GEO_IP"),
    THREAT_MAP    ("Tehdit Haritası",        "> THREAT_MAP"),
    SUSPICIOUS    ("Şüpheli Trafik",         "> ANOMALY_DET"),
    BLACKLIST     ("Firewall / Kara Liste",  "> FIREWALL"),
    THREAT_INTEL  ("Tehdit İstihbaratı",     "> THREAT_INTEL"),
    THREAT_EVENTS ("Olay Günlüğü",           "> EVENT_LOG"),
    TRAFFIC_GRAPH ("Trafik Grafiği",         "> TRAFFIC_GRAPH"),
    DNS_LOG       ("DNS Sorguları",          "> DNS_LOG"),
    REPORT        ("Rapor & Export",         "> EXPORT"),

    SETTINGS      ("Ayarlar",                "> CONFIG")
}


//  AKTİVİTE

class MainActivity : ComponentActivity() {

    private val vpnRequest = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) launchVpnService(ACTION_START)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val osmdroidBasePath = File(cacheDir, "osmdroid")
        Configuration.getInstance().userAgentValue = packageName
        val prefs = getSharedPreferences("SiberKalkanPrefs", Context.MODE_PRIVATE)
        val savedSyslog = prefs.getString("syslog_ip", "192.168.1.100") ?: "192.168.1.100"
        val savedKey = prefs.getString("abuse_key", "") ?: ""
        NetworkLogState.updateConfig(savedSyslog, savedKey)

        enableEdgeToEdge()
        setContent {
            CyberTheme {
                CyberMonitorApp(
                    onStartClick = { requestVpnPermission() },
                    onStopClick  = { launchVpnService(ACTION_STOP) }
                )
            }
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnRequest.launch(intent) else launchVpnService(ACTION_START)
    }

    private fun launchVpnService(action: String) {
        startService(
            Intent(this, NetworkMonitorService::class.java).apply { this.action = action }
        )
    }

    companion object {
        const val ACTION_START = "START"
        const val ACTION_STOP  = "STOP"
    }
}


//  TEMA

@Composable
fun CyberTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            background = CyberBlack,
            surface    = DarkGray,
            primary    = MatrixGreen
        ),
        content = content
    )
}


//  ANA UYGULAMA SCAFFOLD

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberMonitorApp(onStartClick: () -> Unit, onStopClick: () -> Unit) {
    val drawerState    = rememberDrawerState(DrawerValue.Closed)
    val scope          = rememberCoroutineScope()
    var currentScreen  by remember { mutableStateOf(DrawerScreen.MAIN) }
    var showClearDlg   by remember { mutableStateOf(false) }
    var showInfoDlg    by remember { mutableStateOf(false) } // BİLGİ MENÜSÜ İÇİN STATE EKLENDİ
    var isRunning      by remember { mutableStateOf(false) }

    val allLogs       by NetworkLogState.allLogs.collectAsState()
    val suspLogs      by NetworkLogState.suspiciousLogs.collectAsState()
    val blacklist     by NetworkLogState.blacklist.collectAsState()
    val appBw         by NetworkLogState.appBandwidth.collectAsState()
    val threatEvents  by NetworkLogState.threatEvents.collectAsState()
    val threatCache   by NetworkLogState.threatIntelCache.collectAsState()

    val activeThreatCount = suspLogs.count {
        it.threatScore >= 50 || it.isTorExit || it.isKnownC2 || it.isMalwareUrl
    }

    ModalNavigationDrawer(
        drawerState     = drawerState,
        gesturesEnabled = currentScreen != DrawerScreen.THREAT_MAP,
        drawerContent   = {
            ModalDrawerSheet(
                drawerContainerColor = DarkGray,
                modifier             = Modifier.width(290.dp)
            ) {
                // --- SABİT BAŞLIK KISMI ---
                Column(modifier = Modifier.fillMaxWidth()) {
                    Spacer(Modifier.height(48.dp))
                    Text(
                        " 🛡️  SİBER KALKAN",
                        color       = MatrixGreen,
                        fontFamily  = FontFamily.Monospace,
                        fontWeight  = FontWeight.Bold,
                        fontSize    = 20.sp,
                        modifier    = Modifier.padding(16.dp)
                    )
                    if (activeThreatCount > 0) {
                        Text(
                            "  ⚠️  $activeThreatCount aktif tehdit",
                            color      = AlertRed,
                            fontFamily = FontFamily.Monospace,
                            fontSize   = 12.sp,
                            modifier   = Modifier.padding(horizontal = 16.dp)
                        )
                    }
                    HorizontalDivider(color = MatrixGreen.copy(alpha = 0.2f))
                    Spacer(Modifier.height(12.dp))
                }

                // --- KAYDIRILABİLİR MENÜ KISMI ---
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                ) {
                    DrawerScreen.values().forEach { screen ->
                        val badge = when (screen) {
                            DrawerScreen.SUSPICIOUS    -> if (suspLogs.isNotEmpty()) suspLogs.size.toString() else null
                            DrawerScreen.THREAT_EVENTS -> if (threatEvents.isNotEmpty()) threatEvents.size.toString() else null
                            else -> null
                        }
                        NavigationDrawerItem(
                            label = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(screen.label, fontFamily = FontFamily.Monospace)
                                    if (badge != null) {
                                        Spacer(Modifier.width(6.dp))
                                        Box(
                                            contentAlignment = Alignment.Center,
                                            modifier = Modifier
                                                .background(AlertRed, RoundedCornerShape(8.dp))
                                                .padding(horizontal = 5.dp, vertical = 1.dp)
                                        ) {
                                            Text(badge, color = Color.White, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                        }
                                    }
                                }
                            },
                            selected  = currentScreen == screen,
                            onClick   = { currentScreen = screen; scope.launch { drawerState.close() } },
                            colors    = NavigationDrawerItemDefaults.colors(
                                selectedContainerColor   = MatrixGreen.copy(alpha = 0.12f),
                                unselectedContainerColor = Color.Transparent,
                                selectedTextColor        = MatrixGreen,
                                unselectedTextColor      = MatrixGreen.copy(alpha = 0.65f)
                            ),
                            modifier  = Modifier.padding(horizontal = 12.dp)
                        )
                    }
                    Spacer(Modifier.height(24.dp))
                }
            }
        }
    ) {
        Scaffold(
            modifier  = Modifier.fillMaxSize(),
            topBar    = {
                TopAppBar(
                    title           = {
                        Text(
                            currentScreen.title,
                            color      = MatrixGreen,
                            fontFamily = FontFamily.Monospace,
                            fontSize   = 15.sp
                        )
                    },
                    navigationIcon  = {
                        TextButton(onClick = { scope.launch { drawerState.open() } }) {
                            Text("MENU", color = MatrixGreen, fontWeight = FontWeight.Bold)
                        }
                    },
                    actions         = {
                        // BİLGİ BUTONU EKLENDİ
                        TextButton(onClick = { showInfoDlg = true }) {
                            Text("BİLGİ", color = InfoBlue, fontWeight = FontWeight.Bold)
                        }

                        if (currentScreen != DrawerScreen.BLACKLIST &&
                            currentScreen != DrawerScreen.REPORT) {
                            TextButton(onClick = { showClearDlg = true }) {
                                Text("TEMİZLE", color = AlertRed, fontWeight = FontWeight.Bold)
                            }
                        }
                    },
                    colors          = TopAppBarDefaults.topAppBarColors(containerColor = DarkGray)
                )
            },
            bottomBar = {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .windowInsetsPadding(WindowInsets.navigationBars)
                        .height(40.dp)
                        .background(DarkGray)
                        .border(0.5.dp, MatrixGreen.copy(alpha = 0.3f))
                ) {
                    val statusColor = if (activeThreatCount > 0) AlertRed else MatrixGreen
                    val statusText  = if (isRunning) {
                        if (activeThreatCount > 0)
                            "STATUS: ACTIVE  ⚠ $activeThreatCount THREAT"
                        else
                            "STATUS: ACTIVE  PKT:${allLogs.size}"
                    } else "STATUS: IDLE"
                    Text(
                        statusText,
                        color      = statusColor,
                        fontSize   = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier   = Modifier.align(Alignment.Center)
                    )
                }
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .padding(innerPadding)
                    .fillMaxSize()
                    .background(CyberBlack)
            ) {
                when (currentScreen) {
                    DrawerScreen.MAIN          -> MainContent(isRunning, allLogs, blacklist.size)  {
                        if (isRunning) onStopClick() else onStartClick()
                        isRunning = !isRunning
                    }
                    DrawerScreen.APP_DETECTION -> AppDetectionContent(appBw)
                    DrawerScreen.LOCATION      -> LocationContent(allLogs)
                    DrawerScreen.THREAT_MAP    -> ThreatMapContent(allLogs)
                    DrawerScreen.SUSPICIOUS    -> SuspiciousContent(suspLogs)
                    DrawerScreen.BLACKLIST     -> BlacklistContent(blacklist)
                    DrawerScreen.THREAT_INTEL  -> ThreatIntelContent(suspLogs, threatCache)
                    DrawerScreen.THREAT_EVENTS -> ThreatEventsContent(threatEvents)
                    DrawerScreen.TRAFFIC_GRAPH -> TrafficGraphContent(allLogs)
                    DrawerScreen.DNS_LOG       -> DnsLogContent(allLogs)
                    DrawerScreen.REPORT        -> ReportContent()
                    DrawerScreen.SETTINGS      -> SettingsContent()
                }
            }

            // TEMİZLE DİYALOĞU
            if (showClearDlg) {
                AlertDialog(
                    onDismissRequest = { showClearDlg = false },
                    containerColor   = DarkGray,
                    title  = { Text("ONAY GEREKLİ", color = AlertRed, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold) },
                    text   = { Text("Ekrandaki tüm veriler silinsin mi?", color = MatrixGreen, fontFamily = FontFamily.Monospace) },
                    confirmButton = {
                        TextButton(onClick = { NetworkLogState.clearLogs(); showClearDlg = false }) {
                            Text("SİL", color = AlertRed, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showClearDlg = false }) {
                            Text("VAZGEÇ", color = Color.Gray, fontFamily = FontFamily.Monospace)
                        }
                    }
                )
            }

            // YENİ EKLENEN SİBER SÖZLÜK (BİLGİ) DİYALOĞU
            if (showInfoDlg) {
                CyberDictionaryDialog(onDismiss = { showInfoDlg = false })
            }
        }
    }
}


//  YENİ BİLEŞEN: SİBER SÖZLÜK (BİLGİ EKRANI)

@Composable
fun CyberDictionaryDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = DarkGray,
        title = {
            Text("📚 SİBER KALKAN SÖZLÜĞÜ", color = InfoBlue, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
        },
        text = {
            LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 400.dp)) {
                item {
                    Text("1. AĞ TEMELLERİ", color = MatrixGreen, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 8.dp, bottom = 4.dp))
                }
                item { DictionaryItem("Paket (Packet)", "İnternet üzerindeki veriler tek parça halinde değil, küçük parçalara (paketlere) bölünerek gönderilir.") }
                item { DictionaryItem("Payload", "Bir ağ paketinin içindeki asıl taşınan veri yüküdür (şifreler, mesaj metinleri, dosyalar).") }
                item { DictionaryItem("TCP / UDP", "İletişim kurallarıdır. TCP kargoyu teslim ettiğinde onay ister, UDP ise onaya bakmadan sürekli ve hızlı veri gönderir.") }
                item { DictionaryItem("DNS Sorgusu", "Uygulamaların isimleri IP adreslerine çevirmek için yaptığı rehberlik sorgusudur.") }

                item {
                    Text("2. İSTİHBARAT & ANALİZ", color = MatrixGreen, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 16.dp, bottom = 4.dp))
                }
                item { DictionaryItem("ASN (Aut. System Number)", "İnternet servis sağlayıcılarının veya dev şirketlerin (Örn: Google, Meta) dünya çapındaki resmi kayıt kimliğidir.") }
                item { DictionaryItem("TLS-SNI", "Şifreli HTTPS trafiğinde, paketin şifrelenmemiş tek kısmı olan 'Hedef Web Sitesi' adıdır. Uygulamanın nereye bağlandığını gösterir.") }
                item { DictionaryItem("JA3 Fingerprint", "Uygulamaların şifreleme yaparken kullandığı matematiksel bir imzadır. Zararlı yazılımların parmak izini tespit etmek için kullanılır.") }
                item { DictionaryItem("Tehdit Skoru", "Arka plandaki yapay zeka motorunun, trafiğin şüpheli davranışlarına bakarak 0 ile 100 arasında verdiği tehlike puanıdır.") }
                // Yeni Eklenen İstihbarat Terimleri
                item { DictionaryItem("AbuseIPDB", "Şüpheli IP adreslerinin dünya çapındaki sabıka kaydını tutan veritabanıdır. Tehdit skoru 75 ve üzeri olanları otomatik engeller.") }
                item { DictionaryItem("Feodo Tracker", "Bilinen tehlikeli botnet komuta merkezlerinin (C2) güncel IP listesidir.") }

                item {
                    Text("3. SİBER TEHDİTLER", color = MatrixGreen, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 16.dp, bottom = 4.dp))
                }
                item { DictionaryItem("Botnet C2", "Virüslü cihazların, sahibinden (hacker) emir aldığı veya çaldığı verileri gönderdiği 'Ana Komuta Merkezi' sunucusudur.") }
                item { DictionaryItem("Tor Exit Node", "Kullanıcıların kimliğini gizlemek için kullandığı 'Karanlık Ağ' (Dark Web) çıkış noktasıdır.") }
                item { DictionaryItem("Beaconing", "Bir virüsün 'Ben hayattayım' demek için hacker'ın sunucusuna düzenli kalp atışı gibi (örn. 60 sn'de bir) sinyal göndermesidir.") }
                item { DictionaryItem("Port Scan", "Bir saldırganın, cihazında açık bir kapı bulmak için saniyeler içinde binlerce farklı portu yoklamasıdır.") }
                item { DictionaryItem("Night Exfiltration", "Cihazın sen uyurken (gece 00:00 - 06:00 arası) dışarıya devasa boyutlarda gizlice veri kaçırmasıdır.") }

                // Yeni Eklenen Sistem Mimarisi Terimleri
                item {
                    Text("4. SİSTEM MİMARİSİ", color = MatrixGreen, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 16.dp, bottom = 4.dp))
                }
                item { DictionaryItem("VPN Tüneli (TUN)", "Cihazda root yetkisine ihtiyaç duymadan tüm ağ trafiğini yakalayıp izlemek için oluşturulan sanal ağ arayüzüdür.") }
                item { DictionaryItem("DPI (Derin Paket Analizi)", "Ağ paketlerinin ham byte verilerini inceleyerek şifreli trafiğin bile içeriğini ve nereye gittiğini analiz etme teknolojisidir.") }
                item { DictionaryItem("PCAP Export", "Yakalanan ham ağ paketlerinin Wireshark gibi profesyonel siber güvenlik araçlarıyla incelenebilmesi için kaydedildiği endüstri standardı dosya formatıdır.") }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("ANLADIM", color = MatrixGreen, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
            }
        }
    )
}

@Composable
fun DictionaryItem(term: String, desc: String) {
    Column(modifier = Modifier.padding(vertical = 6.dp)) {
        Text("> $term", color = WarnYellow, fontSize = 13.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
        Text(desc, color = Color.White.copy(alpha = 0.8f), fontSize = 11.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(start = 12.dp, top = 2.dp))
        HorizontalDivider(color = MatrixGreen.copy(alpha = 0.1f), modifier = Modifier.padding(top = 6.dp))
    }
}


//  HAREKETLİ RADAR (PULSE) ANİMASYON SINIFI

data class RadarTarget(val geoPoint: GeoPoint, val color: Int)

class RadarPulseOverlay(private val targets: List<RadarTarget>) : Overlay() {
    private val corePaint = Paint().apply { isAntiAlias = true; style = Paint.Style.FILL }
    private val pulsePaint = Paint().apply { isAntiAlias = true; style = Paint.Style.STROKE; strokeWidth = 5f }
    private val point = Point()
    var isActive = true

    override fun draw(canvas: Canvas, mapView: MapView, shadow: Boolean) {
        if (shadow || !isActive) return

        val proj = mapView.projection
        val time = System.currentTimeMillis()
        val pulseCycle = 1500L
        val progress = (time % pulseCycle) / pulseCycle.toFloat()

        val maxRadius = 50f * mapView.context.resources.displayMetrics.density

        targets.forEach { target ->
            proj.toPixels(target.geoPoint, point)

            corePaint.color = target.color
            canvas.drawCircle(point.x.toFloat(), point.y.toFloat(), 12f, corePaint)

            pulsePaint.color = target.color
            val alpha = ((1f - progress) * 255).toInt()
            pulsePaint.alpha = alpha.coerceIn(0, 255)
            val currentRadius = 12f + (progress * maxRadius)
            canvas.drawCircle(point.x.toFloat(), point.y.toFloat(), currentRadius, pulsePaint)
        }

        if (isActive) mapView.postInvalidateDelayed(50)
    }
}


//  EKRAN İÇERİKLERİ
@Composable
fun ThreatMapContent(logs: List<PacketData>) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val geoLogs = logs.filter { it.lat != 0.0 && it.lon != 0.0 }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("🗺️ CANLI TEHDİT RADARI")
        Text(
            "> Sinyal tespit edildi: ${geoLogs.size} hedef takipte.",
            color = MatrixGreen.copy(alpha = 0.7f),
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Box(
            Modifier
                .fillMaxSize()
                .border(1.dp, MatrixGreen.copy(alpha = 0.5f))
        ) {
            AndroidView(
                factory = { context ->
                    MapView(context).apply {
                        setTileSource(TileSourceFactory.MAPNIK)
                        setMultiTouchControls(true)
                        setBuiltInZoomControls(true)
                        controller.setZoom(2.5)
                        controller.setCenter(GeoPoint(39.0, 35.0))

                        setOnTouchListener { view, _ ->
                            view.parent.requestDisallowInterceptTouchEvent(true)
                            false
                        }

                        val darkMatrix = ColorMatrix().apply {
                            setSaturation(0f)
                            postConcat(ColorMatrix(floatArrayOf(
                                -1f,  0f,  0f, 0f, 255f,
                                0f, -1f,  0f, 0f, 255f,
                                0f,  0f, -1f, 0f, 255f,
                                0f,  0f,  0f, 1f,   0f
                            )))
                        }
                        overlayManager.tilesOverlay.setColorFilter(ColorMatrixColorFilter(darkMatrix))
                    }
                },
                update = { mapView ->
                    mapView.overlays.removeAll {
                        if (it is RadarPulseOverlay) it.isActive = false
                        it is RadarPulseOverlay || it is Marker
                    }

                    val grouped = geoLogs.groupBy { it.ip }
                    val radarTargets = mutableListOf<RadarTarget>()

                    val emptyBitmap = Bitmap.createBitmap(1, 1, Bitmap.Config.ARGB_8888)
                    val transparentIcon = BitmapDrawable(ctx.resources, emptyBitmap)

                    grouped.forEach { (ip, packets) ->
                        val representative = packets.firstOrNull { it.lat != 0.0 && it.lon != 0.0 } ?: return@forEach
                        val maxThreat = packets.maxOf { it.threatScore }

                        val markerColor = when {
                            representative.isKnownC2 || representative.isTorExit || representative.isMalwareUrl -> android.graphics.Color.parseColor("#BB00FF")
                            maxThreat >= 75 -> android.graphics.Color.parseColor("#FF003C")
                            maxThreat >= 40 -> android.graphics.Color.parseColor("#FFD600")
                            else -> android.graphics.Color.parseColor("#00FF41")
                        }

                        val geoPoint = GeoPoint(representative.lat, representative.lon)
                        radarTargets.add(RadarTarget(geoPoint, markerColor))

                        val marker = Marker(mapView)
                        marker.position = geoPoint
                        marker.setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_CENTER)
                        marker.icon = transparentIcon
                        marker.title = ip
                        marker.snippet = "Tehdit: $maxThreat | Pkt: ${packets.size}\n${representative.country}\nApp: ${representative.appName}"
                        mapView.overlays.add(marker)
                    }

                    mapView.overlays.add(RadarPulseOverlay(radarTargets))
                    mapView.invalidate()
                }
            )
        }
    }
}

@Composable
fun MainContent(isRunning: Boolean, logs: List<PacketData>, blCount: Int, onToggle: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Button(
            onClick  = onToggle,
            modifier = Modifier.fillMaxWidth().height(55.dp),
            colors   = ButtonDefaults.buttonColors(
                containerColor = if (isRunning) AlertRed.copy(alpha = 0.15f) else DarkGray
            ),
            shape    = RoundedCornerShape(4.dp),
            border   = BorderStroke(1.dp, if (isRunning) AlertRed else MatrixGreen)
        ) {
            Text(
                if (isRunning) "[ STOP_PROTOCOL ]" else "[ START_PROTOCOL ]",
                color      = if (isRunning) AlertRed else MatrixGreen,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(Modifier.height(12.dp))

        val highScore = logs.maxOfOrNull { it.threatScore } ?: 0
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            StatChip("PKT",   logs.size.toString(),                             MatrixGreen)
            StatChip("SUSP",  logs.count { it.isSuspicious }.toString(),        WarnYellow)
            StatChip("SCORE", highScore.toString(),                             if (highScore >= 75) AlertRed else MatrixGreen)
            StatChip("BL",    blCount.toString(),                              AlertRed)
        }

        Spacer(Modifier.height(10.dp))

        Box(
            Modifier
                .fillMaxSize()
                .border(0.5.dp, MatrixGreen.copy(alpha = 0.5f))
                .padding(8.dp)
        ) {
            if (logs.isEmpty()) {
                Text("> Bekleniyor...", color = MatrixGreen.copy(alpha = 0.4f),
                    fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(logs) { log ->
                        val color = when {
                            log.isKnownC2    -> PurpleC2
                            log.isTorExit    -> PurpleC2
                            log.isMalwareUrl -> AlertRed
                            log.threatScore >= 75 -> AlertRed
                            log.isSuspicious -> WarnYellow
                            else             -> MatrixGreen
                        }
                        val icon = when {
                            log.isKnownC2 || log.isTorExit || log.isMalwareUrl -> "☠"
                            log.isSuspicious               -> "⚠"
                            else                           -> " "
                        }
                        Text(
                            "$icon [${log.time}] [${log.appName}] → ${log.effectiveHost}:${log.port} [${log.proto}] ${log.country}",
                            color      = color,
                            fontSize   = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines   = 1,
                            overflow   = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun StatChip(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .background(DarkGray, RoundedCornerShape(4.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp)) {
        Text(value, color = color,       fontSize = 14.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
        Text(label, color = color.copy(alpha = 0.6f), fontSize = 9.sp,  fontFamily = FontFamily.Monospace)
    }
}

@Composable
fun AppDetectionContent(appBw: Map<String, Long>) {
    val sorted = appBw.entries.sortedByDescending { it.value }
    val maxVal = sorted.firstOrNull()?.value?.toFloat() ?: 1f

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("📊 BANT GENİŞLİĞİ VE VERİ TÜKETİMİ")
        Box(Modifier.fillMaxSize().border(1.dp, MatrixGreen.copy(alpha = 0.5f)).padding(8.dp)) {
            LazyColumn(Modifier.fillMaxSize()) {
                items(sorted) { (app, bytes) ->
                    val mb    = bytes / 1024.0 / 1024.0
                    val pct   = bytes.toFloat() / maxVal
                    Column(Modifier.padding(vertical = 5.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(app, color = MatrixGreen, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                                modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("%.2f MB".format(mb), color = MatrixGreen, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                        Spacer(Modifier.height(2.dp))
                        Box(Modifier.fillMaxWidth().height(4.dp).background(DarkGray)) {
                            Box(Modifier.fillMaxWidth(pct).height(4.dp).background(MatrixGreen))
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun LocationContent(logs: List<PacketData>) {
    val grouped = remember(logs) {
        logs.filter { it.country != "Sorgulanıyor..." && it.country.isNotEmpty() }
            .groupBy { it.ip }
            .entries
            .sortedByDescending { it.value.size }
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("🌍 KIZIL BÖLGELER VE KONUM TESPİTİ")
        Text("> Otomatik engellenen bölgeler: RU · CN · IR · KP · SY · CU",
            color = AlertRed, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(bottom = 8.dp))
        Text("> ${grouped.size} benzersiz IP",
            color = MatrixGreen.copy(alpha = 0.6f), fontSize = 11.sp, fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(bottom = 8.dp))
        Box(Modifier.fillMaxSize().border(1.dp, MatrixGreen.copy(alpha = 0.5f)).padding(8.dp)) {
            LazyColumn(Modifier.fillMaxSize()) {
                items(grouped) { (ip, packets) ->
                    val first = packets.first()
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 3.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(first.country, color = MatrixGreen, fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1.2f))
                        Text(ip, color = MatrixGreen.copy(alpha = 0.8f), fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1.3f))
                        Text("×${packets.size}  ${first.appName}",
                            color = MatrixGreen.copy(alpha = 0.6f), fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f),
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    HorizontalDivider(color = MatrixGreen.copy(alpha = 0.08f))
                }
            }
        }
    }
}

@Composable
fun SuspiciousContent(logs: List<PacketData>) {
    var detailLog by remember { mutableStateOf<PacketData?>(null) }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("⚠️ PAYLOAD & ANOMALİ TESPİTİ")
        Text("> Detayları görmek ve engellemek için kayda tıklayın.", color = MatrixGreen.copy(alpha = 0.7f),
            fontSize = 11.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(bottom = 8.dp))
        Box(Modifier.fillMaxSize().border(1.dp, AlertRed.copy(alpha = 0.5f)).padding(8.dp)) {
            LazyColumn(Modifier.fillMaxSize()) {
                items(logs) { log ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clickable { detailLog = log }
                            .padding(vertical = 6.dp)
                    ) {
                        val badgeColor = when {
                            log.isKnownC2 || log.isTorExit || log.isMalwareUrl -> PurpleC2
                            log.threatScore >= 75          -> AlertRed
                            else                           -> WarnYellow
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            ThreatBadge(log.threatScore, badgeColor)
                            Spacer(Modifier.width(6.dp))
                            Text("[${log.time}] ${log.ip}:${log.port}",
                                color = badgeColor, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold)
                        }
                        Text("Anomali: ${log.anomalyType}", color = WarnYellow, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        if (log.effectiveHost.isNotEmpty()) {
                            Text("Domain: ${log.effectiveHost}", color = InfoBlue, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        }
                        if (log.tlsSni.isNotEmpty()) {
                            Text("TLS-SNI: ${log.tlsSni}", color = InfoBlue, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        }
                        if (log.payload.isNotEmpty()) {
                            Text("Payload: ${log.payload.take(120)}", color = Color.Yellow, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        }
                        if (log.isTorExit) Text("☠ TOR EXIT NODE", color = PurpleC2, fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        if (log.isKnownC2) Text("☠ BOTNET C2 SUNUCUSU", color = PurpleC2, fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        if (log.isMalwareUrl) Text("☠ MALWARE DOMAIN (URLHaus)", color = AlertRed, fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        HorizontalDivider(color = AlertRed.copy(alpha = 0.1f), modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
        }
    }

    detailLog?.let { log ->
        AlertDialog(
            onDismissRequest = { detailLog = null },
            containerColor   = DarkGray,
            title  = { Text("IP İSTİHBARAT DETAYI: ${log.ip}", color = MatrixGreen, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold) },
            text   = {
                Column {
                    StatRow("Uygulama",     log.appName)
                    StatRow("Domain/SNI",   log.effectiveHost)
                    StatRow("Ülke",         log.country)
                    StatRow("Anomali",      log.anomalyType)
                    StatRow("Tehdit Skoru", log.threatScore.toString())
                    if (log.ja3.isNotEmpty()) StatRow("JA3 Hash", log.ja3)
                    Spacer(Modifier.height(8.dp))
                    Text("> WHOIS/ASN Zenginleştirmesi yapıldı.", color = Color.Gray, fontSize = 10.sp)
                }
            },
            confirmButton = {
                TextButton(onClick = { NetworkLogState.addToBlacklist(log.ip); detailLog = null }) {
                    Text("KARA LİSTEYE AL", color = AlertRed, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { detailLog = null }) {
                    Text("KAPAT", color = Color.Gray)
                }
            }
        )
    }
}

@Composable
fun BlacklistContent(blacklist: Set<String>) {
    var selectedIp by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("⛔ RUST FIREWALL — KARA LİSTE")
        Text("> Engeli kaldırmak için kayda tıklayın.", color = MatrixGreen.copy(alpha = 0.7f),
            fontSize = 11.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(bottom = 8.dp))
        Box(Modifier.fillMaxSize().border(1.dp, AlertRed.copy(alpha = 0.5f)).padding(8.dp)) {
            if (blacklist.isEmpty()) {
                Text("> Kara liste boş.", color = MatrixGreen.copy(alpha = 0.4f), fontFamily = FontFamily.Monospace)
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(blacklist.toList()) { ip ->
                    Text(
                        "❌  $ip",
                        color      = AlertRed,
                        fontSize   = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        modifier   = Modifier
                            .fillMaxWidth()
                            .clickable { selectedIp = ip }
                            .padding(vertical = 8.dp)
                    )
                }
            }
        }
    }

    if (selectedIp != null) {
        AlertDialog(
            onDismissRequest = { selectedIp = null },
            containerColor   = DarkGray,
            title  = { Text("ENGELİ KALDIR", color = MatrixGreen, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold) },
            text   = { Text("$selectedIp engelini kaldırmak istiyor musunuz?", color = MatrixGreen, fontFamily = FontFamily.Monospace) },
            confirmButton = {
                TextButton(onClick = { NetworkLogState.removeFromBlacklist(selectedIp!!); selectedIp = null }) {
                    Text("ONAYLA", color = MatrixGreen, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                }
            },
            dismissButton = {
                TextButton(onClick = { selectedIp = null }) {
                    Text("İPTAL", color = Color.Gray, fontFamily = FontFamily.Monospace)
                }
            }
        )
    }
}

@Composable
fun ThreatIntelContent(logs: List<PacketData>, cache: Map<String, NetworkLogState.ThreatIntelResult>) {
    val highRisk = logs
        .filter  { it.threatScore > 0 || it.isTorExit || it.isKnownC2 || it.abuseScore > 0 || it.isMalwareUrl }
        .distinctBy { it.ip }
        .sortedByDescending { maxOf(it.threatScore, it.abuseScore.coerceAtLeast(0)) }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("🔍 TEHDİT İSTİHBARATI")
        Row(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            LegendDot(PurpleC2,    "Tor/C2")
            Spacer(Modifier.width(10.dp))
            LegendDot(AlertRed,    "Yüksek Risk")
            Spacer(Modifier.width(10.dp))
            LegendDot(WarnYellow,  "Orta Risk")
            Spacer(Modifier.width(10.dp))
            LegendDot(MatrixGreen, "Düşük Risk")
        }
        Box(Modifier.fillMaxSize().border(1.dp, MatrixGreen.copy(alpha = 0.4f)).padding(8.dp)) {
            if (highRisk.isEmpty()) {
                Text("> Tehdit istihbaratı bekleniyor...",
                    color = MatrixGreen.copy(alpha = 0.4f), fontFamily = FontFamily.Monospace)
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(highRisk) { log ->
                    val combined = maxOf(log.threatScore, log.abuseScore.coerceAtLeast(0))
                    val rowColor = when {
                        log.isKnownC2 || log.isTorExit || log.isMalwareUrl -> PurpleC2
                        combined >= 75                  -> AlertRed
                        combined >= 40                  -> WarnYellow
                        else                            -> MatrixGreen
                    }
                    Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            ThreatBadge(combined, rowColor)
                            Spacer(Modifier.width(8.dp))
                            Text(log.ip, color = rowColor, fontSize = 13.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                            Spacer(Modifier.width(8.dp))
                            Text(log.country, color = rowColor.copy(alpha = 0.7f), fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                        Text("Domain: ${log.effectiveHost}", color = rowColor.copy(alpha = 0.8f), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        Text("Anomali: ${log.anomalyType}", color = rowColor.copy(alpha = 0.7f), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        if (log.abuseScore >= 0) Text("AbuseIPDB: %${log.abuseScore}", color = rowColor, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        val flags = buildList {
                            if (log.isTorExit)   add("TOR EXIT")
                            if (log.isKnownC2)   add("C2 BOTNET")
                            if (log.isMalwareUrl)add("MALWARE URL")
                            if (log.isBeaconing) add("BEACONING")
                            if (log.isPortScan)  add("PORT SCAN")
                            if (log.isNightExfil)add("NIGHT EXFIL")
                        }
                        if (flags.isNotEmpty()) {
                            Text(flags.joinToString(" · "), color = PurpleC2, fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        }
                        HorizontalDivider(color = rowColor.copy(alpha = 0.1f), modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun ThreatEventsContent(events: List<ThreatEvent>) {
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("📋 OLAY GÜNLÜĞÜ (TIMELINE)")
        Box(Modifier.fillMaxSize().border(1.dp, WarnYellow.copy(alpha = 0.4f)).padding(8.dp)) {
            if (events.isEmpty()) {
                Text("> Henüz olay yok.", color = MatrixGreen.copy(alpha = 0.4f), fontFamily = FontFamily.Monospace)
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(events) { event ->
                    val timeStr = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                        .format(java.util.Date(event.timestamp))
                    val color = when {
                        event.threatScore >= 75 -> AlertRed
                        event.threatScore >= 40 -> WarnYellow
                        else                    -> MatrixGreen
                    }
                    Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("[$timeStr]", color = color.copy(alpha = 0.7f), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                            Spacer(Modifier.width(6.dp))
                            ThreatBadge(event.threatScore, color)
                            Spacer(Modifier.width(6.dp))
                            Text(event.ip, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        }
                        Text("App: ${event.appName}  Anomali: ${event.anomalyType}",
                            color = color.copy(alpha = 0.8f), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        if (event.details.isNotEmpty()) {
                            Text(event.details, color = Color.Yellow, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        }
                        HorizontalDivider(color = color.copy(alpha = 0.1f), modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun TrafficGraphContent(logs: List<PacketData>) {
    val buckets = remember(logs) {
        val now    = System.currentTimeMillis()
        val result = IntArray(30)
        logs.forEach { log ->
            val secAgo = ((now - log.timestampMillis) / 1000).toInt()
            if (secAgo in 0..29) {
                val idx = 29 - secAgo
                result[idx]++
            }
        }
        result.toList()
    }
    val maxVal = buckets.maxOrNull()?.toFloat()?.coerceAtLeast(1f) ?: 1f

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("📈 CANLI TRAFİK GRAFİĞİ")
        Text("> Son ${logs.size} paket  |  Pik: ${"%.0f".format(maxVal)} pkt/s",
            color = MatrixGreen.copy(alpha = 0.7f), fontSize = 11.sp, fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(bottom = 8.dp))

        Canvas(
            Modifier
                .fillMaxWidth()
                .height(200.dp)
                .border(0.5.dp, MatrixGreen.copy(alpha = 0.3f))
                .padding(8.dp)
        ) {
            val w    = size.width
            val h    = size.height
            val step = w / (buckets.size - 1).toFloat()

            for (i in 0..4) {
                val y = h * i / 4
                drawLine(MatrixGreen.copy(alpha = 0.1f), Offset(0f, y), Offset(w, y), strokeWidth = 1f)
            }

            val path = Path()
            buckets.forEachIndexed { i, v ->
                val x = i * step
                val y = h - (v / maxVal) * h
                if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            val fillPath = Path().apply {
                addPath(path)
                lineTo((buckets.size - 1) * step, h)
                lineTo(0f, h)
                close()
            }
            drawPath(fillPath, MatrixGreen.copy(alpha = 0.08f))
            drawPath(path, MatrixGreen, style = Stroke(width = 2f))

            buckets.forEachIndexed { i, v ->
                val x = i * step
                val y = h - (v / maxVal) * h
                drawCircle(MatrixGreen, radius = 3f, center = Offset(x, y))
            }

            drawContext.canvas.nativeCanvas.apply {
                val paint = android.graphics.Paint().apply {
                    color    = MatrixGreen.copy(alpha = 0.5f).toArgb()
                    textSize = 24f
                }
                drawText("0s", 0f, h, paint)
                drawText("30s", w - 60f, h, paint)
                drawText("${"%.0f".format(maxVal)} pkt", 0f, 28f, paint)
            }
        }

        Spacer(Modifier.height(16.dp))

        SectionHeader("PROTOKOL DAĞILIMI")
        val tcpCount = logs.count { it.proto == "TCP" }
        val udpCount = logs.count { it.proto == "UDP" }
        val total    = (tcpCount + udpCount).coerceAtLeast(1).toFloat()
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth().height(24.dp).clip(RoundedCornerShape(4.dp))) {
            Box(Modifier.weight(tcpCount / total).fillMaxHeight().background(InfoBlue)) {}
            Box(Modifier.weight(udpCount / total).fillMaxHeight().background(MatrixGreen)) {}
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("TCP: $tcpCount", color = InfoBlue,    fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            Text("UDP: $udpCount", color = MatrixGreen, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
fun DnsLogContent(logs: List<PacketData>) {
    val dnsLogs = logs.filter { it.dnsQuery.isNotEmpty() }
    val grouped = dnsLogs.groupBy { it.dnsQuery }.entries.sortedByDescending { it.value.size }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("🔎 DNS SORGU GÜNLÜĞÜ")
        Text("> Toplam ${dnsLogs.size} DNS sorgusu  |  ${grouped.size} benzersiz domain",
            color = MatrixGreen.copy(alpha = 0.7f), fontSize = 11.sp, fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(bottom = 8.dp))
        Box(Modifier.fillMaxSize().border(1.dp, InfoBlue.copy(alpha = 0.4f)).padding(8.dp)) {
            if (grouped.isEmpty()) {
                Text("> DNS sorgusu bekleniyor...", color = MatrixGreen.copy(alpha = 0.4f), fontFamily = FontFamily.Monospace)
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(grouped) { (domain, entries) ->
                    val firstEntry = entries.first()
                    val suspicious = entries.any { it.isSuspicious }
                    val color = if (suspicious) WarnYellow else MatrixGreen
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(domain, color = color, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(firstEntry.country, color = color.copy(alpha = 0.6f), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        }
                        Text("×${entries.size}", color = color, fontSize = 12.sp, fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold)
                    }
                    HorizontalDivider(color = MatrixGreen.copy(alpha = 0.08f))
                }
            }
        }
    }
}

@SuppressLint("NewApi")
@Composable
fun ReportContent() {
    val ctx    = androidx.compose.ui.platform.LocalContext.current
    var msg    by remember { mutableStateOf("") }

    val logs   by NetworkLogState.allLogs.collectAsState()
    val events by NetworkLogState.threatEvents.collectAsState()
    val bl     by NetworkLogState.blacklist.collectAsState()

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("📄 RAPOR & EXPORT")

        Spacer(Modifier.height(24.dp))

        CyberButton("📝  Markdown Olay Raporu Oluştur") {
            val file = NetworkLogState.generateIncidentReport(ctx)
            msg = "✅  Rapor kaydedildi: ${file.name}"
        }

        Spacer(Modifier.height(12.dp))

        CyberButton("📤  Olayları JSON Olarak Dışa Aktar (SIEM)") {
            val file = NetworkLogState.exportToJson(ctx)
            msg = "✅  JSON kaydedildi: ${file.name}"
        }

        Spacer(Modifier.height(12.dp))

        CyberButton("📊  Trafiği CSV Olarak Dışa Aktar") {
            val file = NetworkLogState.exportToCsv(ctx)
            msg = "✅  CSV kaydedildi: ${file.name}"
        }

        Spacer(Modifier.height(12.dp))

        CyberButton("📤  Kara Listeyi TXT Olarak Dışa Aktar") {
            try {
                val snapshot = NetworkLogState.blacklist.value
                val fileName = "blacklist_${System.currentTimeMillis()}.txt"
                val content = snapshot.joinToString("\n")

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val contentValues = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SiberKalkan")
                    }
                    val uri = ctx.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                    if (uri != null) {
                        ctx.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { w ->
                            w.write(content)
                        }
                        msg = "✅  ${snapshot.size} IP kaydedildi: $fileName"
                    } else {
                        msg = "❌  Hata: Dosya oluşturulamadı"
                    }
                } else {
                    val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "SiberKalkan")
                    if (!dir.exists()) dir.mkdirs()
                    val file = File(dir, fileName)
                    file.writeText(content)
                    msg = "✅  ${snapshot.size} IP kaydedildi: $fileName"
                }
            } catch (e: Exception) { msg = "❌  Hata: ${e.message}" }
        }

        Spacer(Modifier.height(12.dp))

        CyberButton("🗑️  Tüm Verileri Temizle") {
            NetworkLogState.clearLogs()
            msg = "✅  Tüm veriler temizlendi."
        }

        if (msg.isNotEmpty()) {
            Spacer(Modifier.height(20.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .background(DarkGray, RoundedCornerShape(4.dp))
                    .border(0.5.dp, MatrixGreen.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                    .padding(12.dp)
            ) {
                Text(msg, color = MatrixGreen, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            }
        }

        Spacer(Modifier.height(24.dp))
        HorizontalDivider(color = MatrixGreen.copy(alpha = 0.2f))
        Spacer(Modifier.height(16.dp))

        SectionHeader("OTURUM İSTATİSTİKLERİ")
        Spacer(Modifier.height(8.dp))
        StatRow("Toplam Paket",    logs.size.toString())
        StatRow("Şüpheli Paket",   logs.count { it.isSuspicious }.toString())
        StatRow("Olay Sayısı",     events.size.toString())
        StatRow("Kara Liste",      bl.size.toString())
        StatRow("Tor Exit",        logs.count { it.isTorExit }.toString())
        StatRow("Bilinen C2",      logs.count { it.isKnownC2 }.toString())
        StatRow("Beacon Tespit",   logs.count { it.isBeaconing }.toString())
        StatRow("Port Tarama",     logs.count { it.isPortScan }.toString())
        StatRow("Gece Sızdırma",   logs.count { it.isNightExfil }.toString())
        StatRow("DNS Sorgusu",     logs.count { it.dnsQuery.isNotEmpty() }.toString())
        StatRow("TLS-SNI Tespit",  logs.count { it.tlsSni.isNotEmpty() }.toString())
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsContent() {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val prefs = ctx.getSharedPreferences("SiberKalkanPrefs", Context.MODE_PRIVATE)

    var syslogIp by remember { mutableStateOf(prefs.getString("syslog_ip", "192.168.1.100") ?: "192.168.1.100") }
    var apiKey by remember { mutableStateOf(prefs.getString("abuse_key", "") ?: "") }
    var saveMessage by remember { mutableStateOf("") }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        SectionHeader("⚙️ SİSTEM KONFİGÜRASYONU")
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = syslogIp,
            onValueChange = { syslogIp = it },
            label = { Text("Syslog Sunucu IP", color = MatrixGreen) },
            textStyle = androidx.compose.ui.text.TextStyle(color = MatrixGreen, fontFamily = FontFamily.Monospace),
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MatrixGreen,
                unfocusedBorderColor = MatrixGreen.copy(alpha = 0.5f)
            )
        )

        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = apiKey,
            onValueChange = { apiKey = it },
            label = { Text("AbuseIPDB API Key", color = MatrixGreen) },
            textStyle = androidx.compose.ui.text.TextStyle(color = MatrixGreen, fontFamily = FontFamily.Monospace),
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MatrixGreen,
                unfocusedBorderColor = MatrixGreen.copy(alpha = 0.5f)
            )
        )

        Spacer(Modifier.height(24.dp))

        CyberButton("💾 KAYDET") {
            prefs.edit()
                .putString("syslog_ip", syslogIp)
                .putString("abuse_key", apiKey)
                .apply()
            NetworkLogState.updateConfig(syslogIp, apiKey)
            saveMessage = "✅ Ayarlar başarıyla kaydedildi."
        }

        if (saveMessage.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Text(saveMessage, color = InfoBlue, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }
    }
}


//  ORTAK BİLEŞENLER

@Composable
fun SectionHeader(text: String) {
    Text(
        text,
        color      = MatrixGreen,
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize   = 13.sp,
        modifier   = Modifier.padding(bottom = 10.dp)
    )
}

@Composable
fun ThreatBadge(score: Int, color: Color) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .background(color.copy(alpha = 0.2f), RoundedCornerShape(3.dp))
            .border(0.5.dp, color, RoundedCornerShape(3.dp))
            .padding(horizontal = 5.dp, vertical = 1.dp)
    ) {
        Text("$score", color = color, fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun LegendDot(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).background(color, RoundedCornerShape(50)))
        Spacer(Modifier.width(4.dp))
        Text(label, color = color, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
fun CyberButton(label: String, onClick: () -> Unit) {
    Button(
        onClick  = onClick,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        colors   = ButtonDefaults.buttonColors(containerColor = DarkGray),
        shape    = RoundedCornerShape(4.dp),
        border   = BorderStroke(1.dp, MatrixGreen.copy(alpha = 0.7f))
    ) {
        Text(label, color = MatrixGreen, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
    }
}

@Composable
fun StatRow(label: String, value: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = MatrixGreen.copy(alpha = 0.7f), fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        Text(value, color = MatrixGreen,                    fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
    }
}