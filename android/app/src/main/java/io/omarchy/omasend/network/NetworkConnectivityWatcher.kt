package io.omarchy.omasend.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class ConnectionType {
    NONE,
    WIFI,
    CELLULAR,
    ETHERNET,
    OTHER
}

data class NetworkState(
    val isConnected: Boolean = false,
    val connectionType: ConnectionType = ConnectionType.NONE,
    val isLanAvailable: Boolean = false,
    val isMetered: Boolean = false,
    val localIp: String = "127.0.0.1"
)

class NetworkConnectivityWatcher(private val context: Context) {
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val scope = CoroutineScope(Dispatchers.IO)

    private val _networkState = MutableStateFlow(NetworkState())
    val networkState: StateFlow<NetworkState> = _networkState.asStateFlow()

    var onNetworkChanged: ((NetworkState) -> Unit)? = null
    var onLanAvailable: (() -> Unit)? = null
    var onCellularAvailable: (() -> Unit)? = null
    var onNetworkLost: (() -> Unit)? = null

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        if (networkCallback != null) return
        updateCurrentState()

        val builder = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scope.launch {
                    handleNetworkChange()
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                scope.launch {
                    handleNetworkChange()
                }
            }

            override fun onLost(network: Network) {
                scope.launch {
                    handleNetworkChange()
                }
            }
        }

        try {
            connectivityManager?.registerNetworkCallback(builder.build(), callback)
            networkCallback = callback
        } catch (_: Exception) {
            try {
                connectivityManager?.registerDefaultNetworkCallback(callback)
                networkCallback = callback
            } catch (_: Exception) {}
        }
    }

    fun stop() {
        networkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
            networkCallback = null
        }
    }

    fun forceRefresh() {
        scope.launch {
            handleNetworkChange()
        }
    }

    private fun handleNetworkChange() {
        val oldState = _networkState.value
        val newState = computeCurrentState()
        _networkState.value = newState

        if (oldState != newState) {
            onNetworkChanged?.invoke(newState)
            if (!oldState.isLanAvailable && newState.isLanAvailable) {
                onLanAvailable?.invoke()
            }
            if (oldState.connectionType != ConnectionType.CELLULAR && newState.connectionType == ConnectionType.CELLULAR) {
                onCellularAvailable?.invoke()
            }
            if (oldState.isConnected && !newState.isConnected) {
                onNetworkLost?.invoke()
            }
        }
    }

    private fun updateCurrentState() {
        val state = computeCurrentState()
        _networkState.value = state
    }

    fun computeCurrentState(): NetworkState {
        val cm = connectivityManager ?: return NetworkState()
        val activeNetwork = cm.activeNetwork ?: return NetworkState()
        val capabilities = cm.getNetworkCapabilities(activeNetwork) ?: return NetworkState()

        val isConnected = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        val type = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> ConnectionType.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> ConnectionType.ETHERNET
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> ConnectionType.CELLULAR
            else -> ConnectionType.OTHER
        }

        val isLan = type == ConnectionType.WIFI || type == ConnectionType.ETHERNET
        val isMetered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val localIp = NetworkUtils.getLocalIpAddress()

        return NetworkState(
            isConnected = isConnected,
            connectionType = type,
            isLanAvailable = isLan && localIp != "127.0.0.1",
            isMetered = isMetered,
            localIp = localIp
        )
    }
}
