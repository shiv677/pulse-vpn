package com.shivansh.pulsevpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.util.concurrent.atomic.AtomicBoolean

class PulseVpnService : VpnService() {

    companion object {
        const val CHANNEL_ID = "pulse_vpn_tunnel_channel"
        const val CHANNEL_NAME = "Pulse VPN Active Tunnel"
        const val NOTIFICATION_ID = 4102

        const val ACTION_CONNECT = "com.shivansh.pulsevpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.shivansh.pulsevpn.ACTION_DISCONNECT"

        const val EXTRA_ADDRESS = "address"
        const val EXTRA_DNS = "dns"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_ENDPOINT = "endpoint"
        const val EXTRA_ALLOWED_APPS = "allowed_packages"
        const val EXTRA_DISALLOWED_APPS = "disallowed_packages"
        const val EXTRA_BLOCKING = "blocking_enabled"

        @Volatile
        var isRunning: Boolean = false
            private set

        @Volatile
        var activeEndpoint: String = ""
            private set
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private val activeFlag = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_CONNECT, null -> {
                val address = intent?.getStringExtra(EXTRA_ADDRESS) ?: "10.8.0.2"
                val dns = intent?.getStringExtra(EXTRA_DNS) ?: "1.1.1.1"
                val rawMtu = intent?.getIntExtra(EXTRA_MTU, 1420) ?: 1420
                val mtu = if (rawMtu in 1280..1420) rawMtu else 1420
                val endpoint = intent?.getStringExtra(EXTRA_ENDPOINT) ?: "Oracle Cloud Exit Node"
                val blocking = intent?.getBooleanExtra(EXTRA_BLOCKING, false) ?: false
                val allowedApps = intent?.getStringArrayListExtra(EXTRA_ALLOWED_APPS) ?: arrayListOf()
                val disallowedApps = intent?.getStringArrayListExtra(EXTRA_DISALLOWED_APPS) ?: arrayListOf()

                startForegroundWithChannel(endpoint)
                establishWireGuardTun(
                    address = address,
                    dns = dns,
                    mtu = mtu,
                    blocking = blocking,
                    allowedApps = allowedApps,
                    disallowedApps = disallowedApps
                )
                activeEndpoint = endpoint
                isRunning = true
                PulseTileService.requestTileStateUpdate(this)
            }
        }
        return START_STICKY
    }

    private fun establishWireGuardTun(
        address: String,
        dns: String,
        mtu: Int,
        blocking: Boolean,
        allowedApps: List<String>,
        disallowedApps: List<String>
    ) {
        stopExistingDescriptor()

        val ipv4Addr = address.split(",").firstOrNull()?.trim()?.split("/")?.firstOrNull() ?: "10.8.0.2"
        val builder = Builder()
            .setSession("Pulse VPN WireGuard")
            .setMtu(mtu)
            .addAddress(ipv4Addr, 32)
            // Split default route 0.0.0.0/1 and 128.0.0.0/1 to override default gateway cleanly
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 1)
            .setBlocking(blocking)

        dns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { server ->
            runCatching { builder.addDnsServer(server) }
        }

        // Enforce mutual exclusion between allowlist and disallowlist
        if (allowedApps.isNotEmpty() && disallowedApps.isEmpty()) {
            allowedApps.forEach { pkg ->
                runCatching { builder.addAllowedApplication(pkg) }
            }
        } else if (disallowedApps.isNotEmpty()) {
            disallowedApps.forEach { pkg ->
                runCatching { builder.addDisallowedApplication(pkg) }
            }
        } else {
            runCatching { builder.addDisallowedApplication(packageName) }
        }

        tunInterface = builder.establish()
        activeFlag.set(tunInterface != null)
    }

    private fun startForegroundWithChannel(endpoint: String) {
        val notification = buildForegroundNotification(endpoint)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Persistent status for active Pulse VPN WireGuard encrypted tunnel"
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(endpoint: String): Notification {
        val disconnectIntent = Intent(this, PulseVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this,
            0,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Pulse VPN • Connected")
            .setContentText("WireGuard tunnel active ($endpoint • MTU 1420)")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_menu_close_clear_cancel,
                    "Disconnect",
                    disconnectPendingIntent
                ).build()
            )
            .build()
    }

    private fun stopExistingDescriptor() {
        runCatching { tunInterface?.close() }
        tunInterface = null
    }

    private fun stopTunnel() {
        activeFlag.set(false)
        stopExistingDescriptor()
        isRunning = false
        activeEndpoint = ""
        PulseTileService.requestTileStateUpdate(this)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
