package com.example.traficinternet.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import androidx.core.app.NotificationCompat;

import com.example.traficinternet.R;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class CaptureVpnService extends VpnService {

    private static final String CHANNEL_ID = "vpn_channel";
    private static final String ACTION_PACKET = "com.example.traficinternet.PACKET";

    private static final String PREFS = "traffic_prefs";
    private static final String KEY_BLOCKLIST = "blocklist";
    private static final String KEY_BLOCKING_ENABLED = "blocking_enabled";
    private static final String ACTION_BLOCKLIST_UPDATED = "com.example.traficinternet.BLOCKLIST_UPDATED";

    private ParcelFileDescriptor vpnInterface;
    private Thread readerThread;
    private volatile boolean running;

    private FileOutputStream tunOut;
    private DatagramSocket dnsSocket;

    private volatile Set<String> cachedBlocklist = new HashSet<>();
    private volatile boolean blockingEnabled = true;

    private BroadcastReceiver updateReceiver;

    @Override
    public void onCreate() {
        super.onCreate();
        loadFilterPrefs();
        registerUpdateReceiver();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(1, createNotification());
        startVpnIfNeeded();
        return Service.START_STICKY;
    }

    private void startVpnIfNeeded() {
        if (vpnInterface != null) return;

        Builder builder = new Builder();
        builder.setSession("TrafficInternet VPN");
        builder.addAddress("10.0.0.2", 32);
        builder.addDnsServer("10.0.0.1");
        builder.addRoute("10.0.0.1", 32);

        vpnInterface = builder.establish();
        if (vpnInterface == null) {
            sendLine("VPN establish failed");
            stopSelf();
            return;
        }

        running = true;
        startReaderThread();
        sendLine("VPN established (DNS-only)");
    }

    private void loadFilterPrefs() {
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        blockingEnabled = prefs.getBoolean(KEY_BLOCKING_ENABLED, true);
        Set<String> set = prefs.getStringSet(KEY_BLOCKLIST, new HashSet<>());
        cachedBlocklist = new HashSet<>(set);
    }

    private void registerUpdateReceiver() {
        if (updateReceiver != null) return;

        updateReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                loadFilterPrefs();
                sendLine("Filter updated. Blocking=" + (blockingEnabled ? "ON" : "OFF") + " | items=" + cachedBlocklist.size());
            }
        };

        IntentFilter f = new IntentFilter(ACTION_BLOCKLIST_UPDATED);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(updateReceiver, f, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(updateReceiver, f);
        }
    }

    @Override
    public void onDestroy() {
        running = false;

        try { if (readerThread != null) readerThread.interrupt(); } catch (Exception ignored) {}
        try { if (dnsSocket != null) dnsSocket.close(); } catch (Exception ignored) {}
        try { if (tunOut != null) tunOut.close(); } catch (Exception ignored) {}

        try {
            if (vpnInterface != null) {
                vpnInterface.close();
                vpnInterface = null;
            }
        } catch (Exception ignored) {}

        try { if (updateReceiver != null) unregisterReceiver(updateReceiver); } catch (Exception ignored) {}

        try { stopForeground(true); } catch (Exception ignored) {}

        super.onDestroy();
    }

    private void startReaderThread() {
        if (vpnInterface == null || readerThread != null) return;

        try {
            tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());

            dnsSocket = new DatagramSocket();
            protect(dnsSocket);
            dnsSocket.setSoTimeout(2000);

        } catch (Exception e) {
            running = false;
            sendLine("Init failed: " + e.getMessage());
            stopSelf();
            return;
        }

        readerThread = new Thread(() -> {
            try {
                FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
                ByteBuffer buffer = ByteBuffer.allocate(32767);

                while (running) {
                    buffer.clear();
                    int length = in.read(buffer.array());
                    if (length <= 0) continue;

                    if (handleDnsIfNeeded(buffer.array(), length)) continue;

                    String parsed = parsePacket(buffer.array(), length);
                    if (parsed != null) sendLine(parsed);
                }
            } catch (Exception e) {
                sendLine("Reader stopped: " + e.getMessage());
            }
        }, "vpn-reader");

        readerThread.start();
    }

    private void sendLine(String line) {
        Intent i = new Intent(ACTION_PACKET);
        i.putExtra("line", line);
        sendBroadcast(i);
    }

    private boolean handleDnsIfNeeded(byte[] data, int len) {
        if (len < 28) return false;

        int version = (data[0] >> 4) & 0xF;
        if (version != 4) return false;

        int ihl = (data[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl + 8) return false;

        int protocol = data[9] & 0xFF;
        if (protocol != 17) return false;

        int srcPort = ((data[ihl] & 0xFF) << 8) | (data[ihl + 1] & 0xFF);
        int dstPort = ((data[ihl + 2] & 0xFF) << 8) | (data[ihl + 3] & 0xFF);
        if (dstPort != 53) return false;

        int udpLen = ((data[ihl + 4] & 0xFF) << 8) | (data[ihl + 5] & 0xFF);
        int dnsOff = ihl + 8;
        int dnsLen = udpLen - 8;

        if (dnsLen <= 0 || dnsOff + dnsLen > len) return false;

        String domain = tryParseDnsQName(data, dnsOff, dnsLen);
        if (domain != null) {
            String d = domain.toLowerCase(Locale.US);
            if (d.startsWith("www.")) d = d.substring(4);

            if (blockingEnabled && isBlocked(d)) {
                sendLine("BLOCKED: " + d);
                sendNxDomainResponse(data, len);
                return true;
            } else {
                sendLine("DNS query: " + d);
            }
        }

        try {
            DatagramPacket q = new DatagramPacket(
                    data, dnsOff, dnsLen,
                    InetAddress.getByName("8.8.8.8"), 53
            );
            dnsSocket.send(q);

            byte[] resp = new byte[1500];
            DatagramPacket r = new DatagramPacket(resp, resp.length);
            dnsSocket.receive(r);

            byte[] outPacket = buildIpv4UdpPacket(
                    new byte[]{10, 0, 0, 1},
                    new byte[]{10, 0, 0, 2},
                    53,
                    srcPort,
                    resp,
                    r.getLength()
            );

            tunOut.write(outPacket);
            tunOut.flush();
            return true;

        } catch (Exception e) {
            sendLine("DNS forward failed: " + e.getMessage());
            return true;
        }
    }

    private boolean isBlocked(String domain) {
        for (String b : cachedBlocklist) {
            if (domain.equals(b)) return true;
            if (domain.endsWith("." + b)) return true;
        }
        return false;
    }

    private void sendNxDomainResponse(byte[] request, int len) {
        try {
            byte[] resp = request.clone();

            int ihl = (resp[0] & 0x0F) * 4;
            int dnsOffset = ihl + 8;

            resp[dnsOffset + 2] = (byte) 0x81;
            resp[dnsOffset + 3] = (byte) 0x83;
            resp[dnsOffset + 6] = 0;
            resp[dnsOffset + 7] = 0;

            tunOut.write(resp, 0, len);
            tunOut.flush();
        } catch (Exception e) {
            sendLine("NXDOMAIN failed: " + e.getMessage());
        }
    }

    private String tryParseDnsQName(byte[] data, int off, int len) {
        if (len < 12) return null;
        int p = off + 12;
        int end = off + len;

        StringBuilder sb = new StringBuilder();
        while (p < end) {
            int l = data[p] & 0xFF;
            if (l == 0) break;
            p++;
            if (p + l > end) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < l; i++) {
                char c = (char) (data[p + i] & 0xFF);
                sb.append(c);
            }
            p += l;
            if (sb.length() > 253) return null;
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private byte[] buildIpv4UdpPacket(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                                      byte[] payload, int payloadLen) {

        int ipHeaderLen = 20;
        int udpHeaderLen = 8;
        int totalLen = ipHeaderLen + udpHeaderLen + payloadLen;

        byte[] pkt = new byte[totalLen];

        pkt[0] = 0x45;
        pkt[1] = 0;
        pkt[2] = (byte) ((totalLen >> 8) & 0xFF);
        pkt[3] = (byte) (totalLen & 0xFF);
        pkt[4] = 0;
        pkt[5] = 0;
        pkt[6] = 0;
        pkt[7] = 0;
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[10] = 0;
        pkt[11] = 0;

        System.arraycopy(srcIp, 0, pkt, 12, 4);
        System.arraycopy(dstIp, 0, pkt, 16, 4);

        int csum = ipv4HeaderChecksum(pkt, 0, ipHeaderLen);
        pkt[10] = (byte) ((csum >> 8) & 0xFF);
        pkt[11] = (byte) (csum & 0xFF);

        int u = ipHeaderLen;
        pkt[u] = (byte) ((srcPort >> 8) & 0xFF);
        pkt[u + 1] = (byte) (srcPort & 0xFF);
        pkt[u + 2] = (byte) ((dstPort >> 8) & 0xFF);
        pkt[u + 3] = (byte) (dstPort & 0xFF);

        int udpLen = udpHeaderLen + payloadLen;
        pkt[u + 4] = (byte) ((udpLen >> 8) & 0xFF);
        pkt[u + 5] = (byte) (udpLen & 0xFF);

        pkt[u + 6] = 0;
        pkt[u + 7] = 0;

        System.arraycopy(payload, 0, pkt, ipHeaderLen + udpHeaderLen, payloadLen);

        return pkt;
    }

    private int ipv4HeaderChecksum(byte[] buf, int off, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            int hi = buf[off + i] & 0xFF;
            int lo = buf[off + i + 1] & 0xFF;
            sum += ((hi << 8) | lo);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum) & 0xFFFF;
    }

    private String parsePacket(byte[] data, int len) {
        if (len < 20) return null;

        int version = (data[0] >> 4) & 0xF;
        if (version != 4) return null;

        int ihl = (data[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) return null;

        int protocol = data[9] & 0xFF;

        String srcIp = (data[12] & 0xFF) + "." + (data[13] & 0xFF) + "." + (data[14] & 0xFF) + "." + (data[15] & 0xFF);
        String dstIp = (data[16] & 0xFF) + "." + (data[17] & 0xFF) + "." + (data[18] & 0xFF) + "." + (data[19] & 0xFF);

        if (protocol == 6 || protocol == 17) {
            if (len < ihl + 4) return null;

            int srcPort = ((data[ihl] & 0xFF) << 8) | (data[ihl + 1] & 0xFF);
            int dstPort = ((data[ihl + 2] & 0xFF) << 8) | (data[ihl + 3] & 0xFF);

            String proto = (protocol == 6) ? "TCP" : "UDP";
            String tag = "";
            if (dstPort == 53 || srcPort == 53) tag = " DNS";
            else if (dstPort == 80 || srcPort == 80) tag = " HTTP";
            else if (dstPort == 443 || srcPort == 443) tag = " HTTPS";

            return String.format(Locale.getDefault(),
                    "%s %s:%d -> %s:%d (%dB)%s",
                    proto, srcIp, srcPort, dstIp, dstPort, len, tag);
        }

        return null;
    }

    private Notification createNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "VPN Capture",
                    NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TrafficInternet VPN")
                .setContentText("VPN capture running (DNS-only)")
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .build();
    }
}