package com.example.traficinternet;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.TrafficStats;
import android.net.VpnService;
import android.net.Uri;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.format.Formatter;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.example.traficinternet.vpn.CaptureVpnService;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class MainActivity extends AppCompatActivity {

    private static final int REQ_LOCATION = 1001;
    private static final int REQ_VPN = 200;

    private static final String PREFS = "traffic_prefs";
    private static final String KEY_BLOCKLIST = "blocklist";
    private static final String KEY_BLOCKING_ENABLED = "blocking_enabled";
    private static final String ACTION_BLOCKLIST_UPDATED = "com.example.traficinternet.BLOCKLIST_UPDATED";
    private static final String ACTION_PACKET = "com.example.traficinternet.PACKET";

    private TextView tvNetwork;
    private TextView tvTraffic;

    private ArrayAdapter<String> logAdapter;
    private final ArrayList<String> logs = new ArrayList<>();

    private ArrayAdapter<String> packetAdapter;
    private final ArrayList<String> packets = new ArrayList<>();
    private BroadcastReceiver packetReceiver;

    private SharedPreferences prefs;

    private Switch switchBlocking;
    private EditText etDomain;
    private ArrayAdapter<String> blockedAdapter;
    private final ArrayList<String> blockedList = new ArrayList<>();

    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable trafficUiUpdater = new Runnable() {
        @Override
        public void run() {
            updateTrafficTotals();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);

        tvNetwork = findViewById(R.id.tvNetwork);
        tvTraffic = findViewById(R.id.tvTraffic);

        Button btnStartVpn = findViewById(R.id.btnStartVpn);
        btnStartVpn.setOnClickListener(v -> startVpn());

        ListView listPackets = findViewById(R.id.listPackets);
        packetAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, packets);
        listPackets.setAdapter(packetAdapter);

        ListView listLog = findViewById(R.id.listLog);
        logAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, logs);
        listLog.setAdapter(logAdapter);

        switchBlocking = findViewById(R.id.switchBlocking);
        etDomain = findViewById(R.id.etDomain);
        Button btnAddDomain = findViewById(R.id.btnAddDomain);
        Button btnClearBlocked = findViewById(R.id.btnClearBlocked);

        ListView listBlocked = findViewById(R.id.listBlocked);
        blockedAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, blockedList);
        listBlocked.setAdapter(blockedAdapter);

        switchBlocking.setChecked(prefs.getBoolean(KEY_BLOCKING_ENABLED, true));
        reloadBlockedListUI();

        switchBlocking.setOnCheckedChangeListener((buttonView, isChecked) -> {
            prefs.edit().putBoolean(KEY_BLOCKING_ENABLED, isChecked).apply();
            notifyServiceBlocklistUpdated();
            addLog("Blocking " + (isChecked ? "ENABLED" : "DISABLED"));
        });

        btnAddDomain.setOnClickListener(v -> {
            String domain = normalizeDomain(etDomain.getText().toString());
            if (domain == null) {
                Toast.makeText(this, "Invalid domain", Toast.LENGTH_SHORT).show();
                return;
            }

            Set<String> set = new HashSet<>(prefs.getStringSet(KEY_BLOCKLIST, new HashSet<>()));
            if (set.add(domain)) {
                prefs.edit().putStringSet(KEY_BLOCKLIST, set).apply();
                etDomain.setText("");
                reloadBlockedListUI();
                notifyServiceBlocklistUpdated();
                addLog("Added: " + domain);
            } else {
                Toast.makeText(this, "Already blocked", Toast.LENGTH_SHORT).show();
            }
        });

        listBlocked.setOnItemClickListener((parent, view, position, id) -> {
            String domain = blockedList.get(position);
            Set<String> set = new HashSet<>(prefs.getStringSet(KEY_BLOCKLIST, new HashSet<>()));
            if (set.remove(domain)) {
                prefs.edit().putStringSet(KEY_BLOCKLIST, set).apply();
                reloadBlockedListUI();
                notifyServiceBlocklistUpdated();
                addLog("Removed: " + domain);
            }
        });

        btnClearBlocked.setOnClickListener(v -> {
            prefs.edit().putStringSet(KEY_BLOCKLIST, new HashSet<>()).apply();
            reloadBlockedListUI();
            notifyServiceBlocklistUpdated();
            addLog("Blacklist cleared");
        });

        registerPacketReceiver();

        connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        registerNetworkCallback();

        ensureLocationPermissionIfNeeded();
        updateNetworkInfo();
        updateTrafficTotals();
        handler.post(trafficUiUpdater);
    }

    private void startVpn() {
        Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, REQ_VPN);
        } else {
            onActivityResult(REQ_VPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            Intent intent = new Intent(this, CaptureVpnService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
            addLog("VPN started");
        }
    }

    private void registerPacketReceiver() {
        if (packetReceiver != null) return;

        packetReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String line = intent.getStringExtra("line");
                if (line == null) return;

                packets.add(0, line);
                if (packets.size() > 200) packets.remove(packets.size() - 1);
                packetAdapter.notifyDataSetChanged();
            }
        };

        IntentFilter filter = new IntentFilter(ACTION_PACKET);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(packetReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(packetReceiver, filter);
        }
    }

    private void notifyServiceBlocklistUpdated() {
        sendBroadcast(new Intent(ACTION_BLOCKLIST_UPDATED));
    }

    private void reloadBlockedListUI() {
        Set<String> set = prefs.getStringSet(KEY_BLOCKLIST, new HashSet<>());
        blockedList.clear();
        blockedList.addAll(set);
        Collections.sort(blockedList, String::compareToIgnoreCase);
        blockedAdapter.notifyDataSetChanged();
    }

    private String normalizeDomain(String input) {
        if (input == null) return null;

        String s = input.trim().toLowerCase(Locale.US);
        if (s.isEmpty()) return null;

        if (s.startsWith("http://") || s.startsWith("https://")) {
            try {
                Uri uri = Uri.parse(s);
                String host = uri.getHost();
                if (host == null) return null;
                s = host.toLowerCase(Locale.US);
            } catch (Exception e) {
                return null;
            }
        }

        if (s.startsWith("www.")) s = s.substring(4);
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);

        if (!s.contains(".") || s.length() < 3) return null;
        if (s.contains(" ")) return null;

        return s;
    }

    private void registerNetworkCallback() {
        if (networkCallback != null || connectivityManager == null) return;

        NetworkRequest request = new NetworkRequest.Builder().build();

        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(@NonNull Network network) {
                runOnUiThread(() -> {
                    addLog("Network available");
                    updateNetworkInfo();
                });
            }

            @Override
            public void onLost(@NonNull Network network) {
                runOnUiThread(() -> {
                    addLog("Network lost");
                    updateNetworkInfo();
                });
            }

            @Override
            public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities networkCapabilities) {
                runOnUiThread(() -> {
                    addLog("Capabilities changed");
                    updateNetworkInfo();
                });
            }
        };

        connectivityManager.registerNetworkCallback(request, networkCallback);
    }

    private void updateNetworkInfo() {
        if (connectivityManager == null) return;

        Network active = connectivityManager.getActiveNetwork();
        if (active == null) {
            tvNetwork.setText("Network: DISCONNECTED");
            return;
        }

        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(active);
        if (caps == null) {
            tvNetwork.setText("Network: UNKNOWN");
            return;
        }

        StringBuilder sb = new StringBuilder("Network: ");

        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            sb.append("Wi-Fi");
            String ssid = getCurrentSsidSafe();
            if (ssid != null) sb.append(" (").append(ssid).append(")");
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            sb.append("Mobile Data");
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            sb.append("Ethernet");
        } else {
            sb.append("Other");
        }

        String ip = getWifiIpIfAny();
        if (ip != null) sb.append("\nIP: ").append(ip);

        tvNetwork.setText(sb.toString());
    }

    private void updateTrafficTotals() {
        long rx = TrafficStats.getTotalRxBytes();
        long tx = TrafficStats.getTotalTxBytes();
        tvTraffic.setText("Traffic total:\nRX: " + formatBytes(rx) + "\nTX: " + formatBytes(tx));
    }

    private String getWifiIpIfAny() {
        try {
            WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifiManager == null) return null;
            WifiInfo info = wifiManager.getConnectionInfo();
            if (info == null) return null;
            int ipInt = info.getIpAddress();
            if (ipInt == 0) return null;
            return Formatter.formatIpAddress(ipInt);
        } catch (Exception e) {
            return null;
        }
    }

    private String getCurrentSsidSafe() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            return null;
        }
        try {
            WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifiManager == null) return null;
            WifiInfo info = wifiManager.getConnectionInfo();
            if (info == null) return null;

            String ssid = info.getSSID();
            if (ssid == null) return null;

            if (ssid.startsWith("\"") && ssid.endsWith("\"") && ssid.length() > 2) {
                ssid = ssid.substring(1, ssid.length() - 1);
            }
            if ("<unknown ssid>".equalsIgnoreCase(ssid)) return null;
            return ssid;
        } catch (Exception e) {
            return null;
        }
    }

    private void ensureLocationPermissionIfNeeded() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.ACCESS_FINE_LOCATION},
                    REQ_LOCATION);
        }
    }

    private void addLog(String msg) {
        if (logAdapter == null) return;
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        logs.add(0, ts + "  " + msg);
        if (logs.size() > 200) logs.remove(logs.size() - 1);
        logAdapter.notifyDataSetChanged();
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return String.format(Locale.getDefault(), "%.1f KB", kb);
        double mb = kb / 1024.0;
        if (mb < 1024) return String.format(Locale.getDefault(), "%.1f MB", mb);
        double gb = mb / 1024.0;
        return String.format(Locale.getDefault(), "%.2f GB", gb);
    }

    @Override
    protected void onDestroy() {
        try {
            if (packetReceiver != null) unregisterReceiver(packetReceiver);
        } catch (Exception ignored) {
        }

        try {
            if (connectivityManager != null && networkCallback != null) {
                connectivityManager.unregisterNetworkCallback(networkCallback);
            }
        } catch (Exception ignored) {
        }

        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_LOCATION) {
            updateNetworkInfo();
            boolean ok = (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED);
            addLog("Location permission " + (ok ? "granted" : "denied") + " (SSID may need it)");
        }
    }
}