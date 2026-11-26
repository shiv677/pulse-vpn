package com.shivansh.pulsevpn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class PulseTileService : TileService() {

    companion object {
        fun requestTileStateUpdate(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                requestListeningState(
                    context,
                    ComponentName(context, PulseTileService::class.java)
                )
            }
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        syncTileState()
    }

    override fun onClick() {
        super.onClick()
        if (PulseVpnService.isRunning) {
            val stopIntent = Intent(this, PulseVpnService::class.java).apply {
                action = PulseVpnService.ACTION_DISCONNECT
            }
            startService(stopIntent)
            updateTile(isConnected = false)
        } else {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                // Launch MainActivity to request user VPN consent
                val activityIntent = Intent(this, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivityAndCollapse(activityIntent)
            } else {
                val startIntent = Intent(this, PulseVpnService::class.java).apply {
                    action = PulseVpnService.ACTION_CONNECT
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(startIntent)
                } else {
                    startService(startIntent)
                }
                updateTile(isConnected = true)
            }
        }
    }

    private fun syncTileState() {
        updateTile(isConnected = PulseVpnService.isRunning)
    }

    private fun updateTile(isConnected: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (isConnected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "Pulse VPN"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (isConnected) "Protected" else "Disconnected"
        }
        tile.updateTile()
    }
}
