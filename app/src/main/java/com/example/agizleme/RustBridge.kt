package com.example.agizleme

import android.content.Context

object RustBridge {
    var appContext: Context? = null

    init {
        System.loadLibrary("agizleme")
    }

    /** VPN fd'sini ve geri çağırma objesini Rust'a iletir; Rust ayrı thread açar. */
    external fun startNativeMonitor(fd: Int, callback: RustBridge)

    /** Kara listeyi virgülle ayrılmış IP dizgisi olarak Rust'a gönderir. */
    external fun updateBlacklist(ips: String)

    /**
     * Rust tarafından JNI üzerinden çağrılır.
     * Gelen JSON mesajını [NetworkLogState.addLog]'a iletir.
     */
    fun onNetworkDataReceived(message: String) {
        NetworkLogState.addLog(message)
    }
}