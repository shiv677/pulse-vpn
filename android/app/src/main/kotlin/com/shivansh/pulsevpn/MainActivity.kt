package com.shivansh.pulsevpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    companion object {
        private const val CONTROL_CHANNEL = "com.pulsevpn.engine/control"
        private const val VPN_PERMISSION_REQUEST_CODE = 1001
    }

    private var pendingConnectArgs: Map<String, Any?>? = null
    private var pendingResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CONTROL_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "connect" -> {
                        val args = call.arguments as? Map<String, Any?> ?: emptyMap()
                        val prepareIntent = VpnService.prepare(this)
                        if (prepareIntent != null) {
                            pendingConnectArgs = args
                            pendingResult = result
                            startActivityForResult(prepareIntent, VPN_PERMISSION_REQUEST_CODE)
                        } else {
                            startPulseVpnService(args)
                            result.success(true)
                        }
                    }
                    "disconnect" -> {
                        val intent = Intent(this, PulseVpnService::class.java).apply {
                            action = PulseVpnService.ACTION_DISCONNECT
                        }
                        startService(intent)
                        result.success(true)
                    }
                    "status" -> {
                        result.success(
                            mapOf(
                                "connected" to PulseVpnService.isRunning,
                                "endpoint" to PulseVpnService.activeEndpoint
                            )
                        )
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun startPulseVpnService(args: Map<String, Any?>) {
        val intent = Intent(this, PulseVpnService::class.java).apply {
            action = PulseVpnService.ACTION_CONNECT
            putExtra(PulseVpnService.EXTRA_ADDRESS, args["address"] as? String ?: "10.8.0.2")
            putExtra(PulseVpnService.EXTRA_DNS, args["dns"] as? String ?: "1.1.1.1")
            putExtra(PulseVpnService.EXTRA_MTU, (args["mtu"] as? Number)?.toInt() ?: 1420)
            putExtra(PulseVpnService.EXTRA_ENDPOINT, args["endpoint"] as? String ?: "Oracle Exit Node")
            putExtra(PulseVpnService.EXTRA_BLOCKING, args["blocking_enabled"] as? Boolean ?: false)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == VPN_PERMISSION_REQUEST_CODE) {
            val callback = pendingResult
            val args = pendingConnectArgs ?: emptyMap()
            pendingResult = null
            pendingConnectArgs = null

            if (resultCode == Activity.RESULT_OK) {
                startPulseVpnService(args)
                callback?.success(true)
            } else {
                callback?.error("VPN_PERMISSION_DENIED", "User rejected VpnService consent", null)
            }
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }
}
