package com.example.agizleme

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat

class NetworkMonitorService : VpnService() {

    companion object {
        private const val CHANNEL_ID   = "siber_kalkan_channel"
        private const val NOTIF_ID     = 1001
        const val ACTION_START         = "START"
        const val ACTION_STOP          = "STOP"
    }

    private var vpnInterface: ParcelFileDescriptor? = null


    //  Servis Yaşam Döngüsü

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP  -> stopVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        closeVpnInterface()
    }

    override fun onRevoke() {
        super.onRevoke()
        closeVpnInterface()
    }


    //  VPN Başlat / Durdur

    private fun startVpn() {
        if (vpnInterface != null) return   // Zaten çalışıyor

        // --- Foreground Service: Android 8+ için zorunlu ---
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_ID, buildNotification(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIF_ID, buildNotification())
        }

        val builder = Builder()
        builder.addAddress("10.0.0.2", 32)
        builder.addRoute("0.0.0.0", 0)                // Tüm IPv4 trafiği
        builder.addDnsServer("8.8.8.8")
        builder.setSession("Siber Kalkan")
        builder.setMtu(1500)

        // Kendi uygulamamızı tünelden çıkar (GeoIP sorguları kesilmesin)
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

        vpnInterface = builder.establish()

        vpnInterface?.let { fd ->
            RustBridge.appContext = applicationContext
            RustBridge.startNativeMonitor(fd.fd, RustBridge)
        }
    }

    private fun stopVpn() {
        closeVpnInterface()
        stopForeground(true)
        stopSelf()
    }

    private fun closeVpnInterface() {
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
    }


    //  Bildirim

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Siber Kalkan",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Ağ izleme servisi aktif" }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, NetworkMonitorService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🛡️ Siber Kalkan Aktif")
            .setContentText("Ağ trafiği izleniyor…")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_delete, "Durdur", stopIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}