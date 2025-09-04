# netviz_eye.py
# Advanced Network Traffic Tool (Visualizer + Anomaly Detector)
# Pitch: A network capture + visualizer with ML/heuristics for anomalies (DDoS, C2 beaconing, exfil), with a GUI.
# -----------------------------------------------------------------------------
import sys
import os
import threading
import time
import queue
import csv
from collections import defaultdict, deque
from datetime import datetime
import math
import random

# ML
from sklearn.ensemble import IsolationForest
import numpy as np

# GUI + plots
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt, QTimer
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Networking
from scapy.all import sniff, get_if_list, TCP, UDP, IP, IPv6, Raw, rdpcap
from netaddr import IPAddress, IPNetwork

# ----------------------------- Utils -----------------------------------------

PRIVATE_NETS = [
    IPNetwork('10.0.0.0/8'),
    IPNetwork('172.16.0.0/12'),
    IPNetwork('192.168.0.0/16'),
    IPNetwork('100.64.0.0/10'),  # CGNAT
    IPNetwork('127.0.0.0/8'),
    IPNetwork('169.254.0.0/16'),
    IPNetwork('::1/128'),
    IPNetwork('fc00::/7'),
    IPNetwork('fe80::/10'),
]

def is_private(ip_str: str) -> bool:
    try:
        ip = IPAddress(ip_str)
        return any(ip in net for net in PRIVATE_NETS)
    except Exception:
        return True  # if unsure, treat as private to reduce false positives

def now_ts():
    return time.time()

def safe_int(x, default=0):
    try: return int(x)
    except: return default

# -------------------------- Data/Model Layer ---------------------------------

class TrafficAggregator:
    """
    Aggregates packets into 1-second bins and keeps rolling windows of stats.
    Provides features for ML and heuristics.
    """
    def __init__(self, window_secs=120):
        self.window_secs = window_secs
        self.bin_size = 1.0
        self.lock = threading.Lock()

        # Rolling structures
        self.bins = deque(maxlen=window_secs)  # each item: dict with stats for that second
        self.bin_timesteps = deque(maxlen=window_secs)  # timestamps per bin start

        self.current_bin_start = math.floor(now_ts())
        self.current_bin = self._blank_bin()

        # Per-host rolling state
        self.host_bytes_out = defaultdict(int)  # src -> bytes out in current window
        self.conn_attempts = defaultdict(lambda: defaultdict(int))  # src -> dst_port -> count
        self.flow_times = defaultdict(list)  # (src,dst) -> list of timestamps (for beaconing)

        # For top talkers
        self.total_bytes_by_host = defaultdict(int)
        self.total_pkts_by_host = defaultdict(int)

    def _blank_bin(self):
        return {
            'pkts': 0,
            'bytes': 0,
            'tcp': 0,
            'udp': 0,
            'other': 0,
            'syn': 0,
            'dns': 0,
            'unique_srcs': set(),
            'unique_dsts': set(),
        }

    def _roll_bin_if_needed(self, pkt_ts):
        # roll if we moved past the 1-second bin boundary
        if pkt_ts >= self.current_bin_start + self.bin_size:
            # Close out current bin
            self.bins.append(self.current_bin)
            self.bin_timesteps.append(self.current_bin_start)
            # Start new bin(s) if multiple seconds jumped
            while pkt_ts >= self.current_bin_start + self.bin_size:
                self.current_bin_start += self.bin_size
            self.current_bin = self._blank_bin()

            # Decay per-window structures roughly aligned with window length
            # (We’ll recompute host_bytes_out each features() call instead of strict decay here.)

    def add_packet(self, pkt, pkt_len):
        ts = math.floor(now_ts())
        with self.lock:
            self._roll_bin_if_needed(ts)
            b = self.current_bin
            b['pkts'] += 1
            b['bytes'] += pkt_len

            ip_src = None
            ip_dst = None
            proto_set = False

            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            elif IPv6 in pkt:
                ip_src = pkt[IPv6].src
                ip_dst = pkt[IPv6].dst

            if TCP in pkt:
                b['tcp'] += 1
                proto_set = True
                flags = pkt[TCP].flags
                # SYN flag set and not ACK -> connection attempt
                if flags & 0x02 and not (flags & 0x10):
                    b['syn'] += 1
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    if ip_src and dport:
                        self.conn_attempts[ip_src][dport] += 1
                # Track flow timing for beaconing detection
                if ip_src and ip_dst:
                    key = (ip_src, ip_dst)
                    self.flow_times[key].append(now_ts())

            elif UDP in pkt:
                b['udp'] += 1
                proto_set = True
                # quick DNS heuristic
                try:
                    dport = pkt[UDP].dport
                    sport = pkt[UDP].sport
                    if dport == 53 or sport == 53:
                        b['dns'] += 1
                except:
                    pass

            if not proto_set:
                b['other'] += 1

            if ip_src: b['unique_srcs'].add(ip_src)
            if ip_dst: b['unique_dsts'].add(ip_dst)

            # Outbound bytes for exfil-esque bursts (very rough: src private -> dst public)
            if ip_src and ip_dst and not is_private(ip_dst) and is_private(ip_src):
                self.host_bytes_out[ip_src] += pkt_len

            # Top talkers (rough totals)
            if ip_src:
                self.total_pkts_by_host[ip_src] += 1
                self.total_bytes_by_host[ip_src] += pkt_len

    def get_recent_bins(self):
        with self.lock:
            # include the current open bin as well
            bins = list(self.bins) + [self.current_bin]
            times = list(self.bin_timesteps) + [self.current_bin_start]
            # Copy sets to lengths to avoid leaking sets
            bins_norm = []
            for b in bins:
                bins_norm.append({
                    'pkts': b['pkts'],
                    'bytes': b['bytes'],
                    'tcp': b['tcp'],
                    'udp': b['udp'],
                    'other': b['other'],
                    'syn': b['syn'],
                    'dns': b['dns'],
                    'unique_srcs': len(b['unique_srcs']),
                    'unique_dsts': len(b['unique_dsts']),
                })
            return times, bins_norm

    def features_per_window(self):
        """
        Aggregate window features for ML (one row).
        """
        times, bins = self.get_recent_bins()
        if len(bins) == 0:
            return None

        pkts = np.array([b['pkts'] for b in bins])
        bytes_arr = np.array([b['bytes'] for b in bins])
        tcp = np.array([b['tcp'] for b in bins])
        udp = np.array([b['udp'] for b in bins])
        other = np.array([b['other'] for b in bins])
        syn = np.array([b['syn'] for b in bins])
        dns = np.array([b['dns'] for b in bins])
        usrc = np.array([b['unique_srcs'] for b in bins])
        udst = np.array([b['unique_dsts'] for b in bins])

        def stats(a):
            return np.array([
                a.mean(), a.std(ddof=1) if a.size > 1 else 0.0,
                a.max() if a.size else 0.0
            ], dtype=float)

        feats = np.hstack([
            stats(pkts),
            stats(bytes_arr),
            stats(tcp),
            stats(udp),
            stats(other),
            stats(syn),
            stats(dns),
            stats(usrc),
            stats(udst),
        ])
        return feats

    def heuristic_alerts(self):
        """
        Return a list of (severity, label, detail) based on rough heuristics.
        """
        alerts = []
        # SYN flood / port scan heuristic: many SYNs or many distinct destination ports
        for src, dports in list(self.conn_attempts.items()):
            distinct_ports = len(dports)
            total_attempts = sum(dports.values())
            if total_attempts >= 200 and distinct_ports >= 50:
                alerts.append(("HIGH", "Port scan / SYN storm",
                               f"Source {src} made {total_attempts} SYN attempts across {distinct_ports} dst ports in the recent window."))

        # Beaconing: regular intervals (low std of inter-arrival) for a flow with many events
        for (src, dst), times in list(self.flow_times.items()):
            if len(times) >= 12:
                intervals = np.diff(times[-40:])  # last up to 40 intervals
                if len(intervals) >= 10:
                    std_ivl = np.std(intervals)
                    mean_ivl = np.mean(intervals)
                    if mean_ivl > 0 and std_ivl < 0.15 * mean_ivl:
                        alerts.append(("MED", "Possible C2 beaconing",
                                       f"Flow {src} → {dst} shows regular intervals (mean ~{mean_ivl:.2f}s, std ~{std_ivl:.2f}s, n={len(intervals)})."))

        # Exfil burst: large outbound bytes to public dests per private src
        for src, byt in list(self.host_bytes_out.items()):
            if byt >= 50 * 1024 * 1024:  # 50MB within window
                alerts.append(("HIGH", "Possible data exfiltration burst",
                               f"Private host {src} sent ~{byt/1024/1024:.1f} MB to public addresses recently."))

        return alerts

    def top_talkers(self, k=10):
        pairs = [(h, self.total_bytes_by_host[h], self.total_pkts_by_host[h]) for h in self.total_bytes_by_host]
        pairs.sort(key=lambda x: x[1], reverse=True)
        return pairs[:k]

    def reset_window_counters(self):
        # decay/clear per-window counters every N seconds to limit growth
        self.host_bytes_out.clear()
        # Trim conn_attempts to keep size small
        for src in list(self.conn_attempts.keys()):
            # keep only most-hit ports
            ports = self.conn_attempts[src]
            if len(ports) > 2000:
                # keep top 1000
                top = dict(sorted(ports.items(), key=lambda kv: kv[1], reverse=True)[:1000])
                self.conn_attempts[src] = top

class AnomalyModel:
    """
    Isolation Forest wrapper with simple lifecycle:
    - collect baseline windows
    - fit model
    - score new windows periodically
    """
    def __init__(self, baseline_needed=60, refit_every=90, random_state=7):
        self.baseline_needed = baseline_needed
        self.refit_every = refit_every
        self.model = None
        self.X_baseline = []
        self.n_since_refit = 0
        self.random_state = random_state

    def add_baseline(self, x):
        if x is not None:
            self.X_baseline.append(x)

    def ready(self):
        return len(self.X_baseline) >= self.baseline_needed

    def fit_if_needed(self):
        if self.ready() and (self.model is None or self.n_since_refit >= self.refit_every):
            X = np.vstack(self.X_baseline)
            self.model = IsolationForest(
                n_estimators=200,
                contamination='auto',
                random_state=self.random_state,
            )
            self.model.fit(X)
            self.n_since_refit = 0

    def score(self, x):
        """
        Returns (is_anom: bool, score: float) where lower score = more anomalous
        """
        if self.model is None or x is None:
            return (False, 0.0)
        self.n_since_refit += 1
        s = float(self.model.score_samples([x])[0])
        # dynamic threshold: anything below (baseline mean - 2.5*std)
        base_scores = self.model.score_samples(np.vstack(self.X_baseline))
        thr = base_scores.mean() - 2.5 * base_scores.std()
        return (s < thr, s)

# ----------------------------- Capture Thread --------------------------------

class CaptureThread(threading.Thread):
    def __init__(self, iface, bpf_filter, pkt_queue, stop_event):
        super().__init__(daemon=True)
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.q = pkt_queue
        self.stop_event = stop_event

    def run(self):
        def _cb(pkt):
            if self.stop_event.is_set():
                return False
            try:
                self.q.put(pkt, timeout=0.01)
            except queue.Full:
                pass
            return True

        try:
            sniff(
                iface=self.iface if self.iface else None,
                prn=_cb,
                store=False,
                filter=self.bpf_filter if self.bpf_filter else None,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            # push an error marker into queue
            self.q.put(("__ERROR__", str(e)))

# ----------------------------- GUI Widgets -----------------------------------

class MplCanvas(FigureCanvas):
    def __init__(self):
        fig = Figure(figsize=(6,4), dpi=100)
        self.ax = fig.add_subplot(111)
        super().__init__(fig)

class NetVizApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EYE — Advanced Network Traffic Visualizer + Anomaly Detector")
        self.resize(1200, 750)

        # State
        self.agg = TrafficAggregator(window_secs=120)
        self.model = AnomalyModel()
        self.pkt_queue = queue.Queue(maxsize=2000)
        self.stop_event = threading.Event()
        self.cap_thread = None
        self.running = False
        self.last_window_reset = now_ts()

        # UI
        self._build_ui()

        # Timers
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._on_tick)
        self.update_timer.start(500)  # 2 times per second

        self.ml_timer = QTimer()
        self.ml_timer.timeout.connect(self._ml_tick)
        self.ml_timer.start(1000)  # once per second

    # ---------------- UI Construction ----------------
    def _build_ui(self):
        tabs = QtWidgets.QTabWidget()
        self.setCentralWidget(tabs)

        # Dashboard
        dash = QtWidgets.QWidget()
        dash_layout = QtWidgets.QVBoxLayout(dash)
        self.rate_canvas = MplCanvas()
        dash_layout.addWidget(QtWidgets.QLabel("Packets per Second (rolling)"))
        dash_layout.addWidget(self.rate_canvas)

        proto_widget = QtWidgets.QWidget()
        proto_layout = QtWidgets.QHBoxLayout(proto_widget)
        self.proto_canvas = MplCanvas()
        self.proto_canvas.ax.set_title("Protocol Mix (last window)")
        proto_layout.addWidget(self.proto_canvas)

        self.top_table = QtWidgets.QTableWidget(0, 3)
        self.top_table.setHorizontalHeaderLabels(["Host", "Bytes (approx)", "Packets"])
        self.top_table.horizontalHeader().setStretchLastSection(True)
        proto_layout.addWidget(self.top_table)

        dash_layout.addWidget(proto_widget)
        tabs.addTab(dash, "Dashboard")

        # Traffic Raw-ish (counts)
        traffic = QtWidgets.QWidget()
        tlay = QtWidgets.QVBoxLayout(traffic)
        self.stats_label = QtWidgets.QLabel("Stats will appear here…")
        self.stats_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tlay.addWidget(self.stats_label)
        tabs.addTab(traffic, "Traffic")

        # Anomalies
        anom = QtWidgets.QWidget()
        alay = QtWidgets.QVBoxLayout(anom)
        self.anom_table = QtWidgets.QTableWidget(0, 4)
        self.anom_table.setHorizontalHeaderLabels(["Time", "Severity", "Type", "Details"])
        self.anom_table.horizontalHeader().setStretchLastSection(True)
        alay.addWidget(self.anom_table)

        btn_row = QtWidgets.QHBoxLayout()
        self.export_btn = QtWidgets.QPushButton("Export Anomalies to CSV")
        self.export_btn.clicked.connect(self.export_anomalies)
        btn_row.addWidget(self.export_btn)

        self.save_plot_btn = QtWidgets.QPushButton("Save Charts as PNG")
        self.save_plot_btn.clicked.connect(self.save_charts)
        btn_row.addWidget(self.save_plot_btn)
        alay.addLayout(btn_row)

        tabs.addTab(anom, "Anomalies")

        # Settings / Controls
        sett = QtWidgets.QWidget()
        slay = QtWidgets.QFormLayout(sett)

        # Interface dropdown
        self.iface_combo = QtWidgets.QComboBox()
        try:
            self.iface_combo.addItem("(default)")
            for iface in get_if_list():
                self.iface_combo.addItem(iface)
        except Exception:
            self.iface_combo.addItem("(default)")
        slay.addRow("Interface:", self.iface_combo)

        # BPF filter
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Optional BPF filter (e.g., tcp or port 53)")
        slay.addRow("Capture Filter:", self.filter_edit)

        # Buttons
        self.start_btn = QtWidgets.QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn = QtWidgets.QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        h = QtWidgets.QHBoxLayout()
        h.addWidget(self.start_btn)
        h.addWidget(self.stop_btn)
        slay.addRow(h)

        # Load PCAP
        self.load_btn = QtWidgets.QPushButton("Load PCAP File…")
        self.load_btn.clicked.connect(self.load_pcap)
        slay.addRow(self.load_btn)

        # Status
        self.status_label = QtWidgets.QLabel("Status: Idle")
        slay.addRow(self.status_label)

        tabs.addTab(sett, "Settings")

        # storage for anomalies
        self.anomaly_rows = []

    # ----------------- Capture Control ----------------
    def start_capture(self):
        if self.running:
            return
        self.stop_event.clear()
        iface = self.iface_combo.currentText()
        iface = None if iface == "(default)" else iface
        bpf = self.filter_edit.text().strip() or None

        self.cap_thread = CaptureThread(iface, bpf, self.pkt_queue, self.stop_event)
        self.cap_thread.start()
        self.running = True
        self.status_label.setText(f"Status: Capturing on {iface or '(default)'} | Filter: {bpf or 'None'}")

    def stop_capture(self):
        if not self.running:
            return
        self.stop_event.set()
        self.running = False
        self.status_label.setText("Status: Stopped")

    def load_pcap(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if not path:
            return
        try:
            pkts = rdpcap(path)
            # feed into queue gradually to simulate time
            for p in pkts:
                self.pkt_queue.put(p)
            QtWidgets.QMessageBox.information(self, "Loaded", f"Loaded {len(pkts)} packets from {os.path.basename(path)}.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "PCAP Error", str(e))

    # ----------------- Periodic Updates ----------------
    def _on_tick(self):
        # Drain queue
        drained = 0
        try:
            while True:
                item = self.pkt_queue.get_nowait()
                if isinstance(item, tuple) and item and item[0] == "__ERROR__":
                    self._append_anomaly("HIGH", "Capture Error", item[1])
                    self.status_label.setText(f"Status: ERROR — {item[1]}")
                    continue
                pkt = item
                pkt_len = int(len(bytes(pkt))) if pkt else 0
                self.agg.add_packet(pkt, pkt_len)
                drained += 1
                if drained >= 1000:
                    break
        except queue.Empty:
            pass

        # Update charts/text
        self._update_rate_plot()
        self._update_proto_plot()
        self._update_top_talkers()
        self._update_stats_label()

        # Periodically reset per-window counters to avoid unbounded growth
        if now_ts() - self.last_window_reset >= 60:
            self.agg.reset_window_counters()
            self.last_window_reset = now_ts()

    def _ml_tick(self):
        feats = self.agg.features_per_window()
        # collect baseline first
        if not self.model.ready():
            if feats is not None:
                self.model.add_baseline(feats)
                self.model.fit_if_needed()
            # Still run heuristics so user sees alerts early
            for sev, typ, detail in self.agg.heuristic_alerts():
                self._append_anomaly(sev, typ, detail)
            return

        self.model.fit_if_needed()
        is_anom, score = self.model.score(feats)
        if is_anom:
            self._append_anomaly("MED", "ML anomaly (IsolationForest)", f"Score={score:.4f}. Window stats look unusual.")
        # Heuristics always
        for sev, typ, detail in self.agg.heuristic_alerts():
            self._append_anomaly(sev, typ, detail)

    # ----------------- UI helpers ----------------
    def _update_rate_plot(self):
        times, bins = self.agg.get_recent_bins()
        y = [b['pkts'] for b in bins]
        ax = self.rate_canvas.ax
        ax.clear()
        ax.plot(range(len(y)), y, linewidth=1.5)
        ax.set_title("Packets / second")
        ax.set_xlabel("Recent seconds")
        ax.set_ylabel("Packets")
        self.rate_canvas.draw_idle()

    def _update_proto_plot(self):
        _, bins = self.agg.get_recent_bins()
        if not bins:
            return
        tcp = sum(b['tcp'] for b in bins)
        udp = sum(b['udp'] for b in bins)
        other = sum(b['other'] for b in bins)
        ax = self.proto_canvas.ax
        ax.clear()
        cats = ["TCP", "UDP", "Other"]
        vals = [tcp, udp, other]
        ax.bar(cats, vals)
        ax.set_ylabel("Count (window)")
        self.proto_canvas.draw_idle()

    def _update_top_talkers(self):
        rows = self.agg.top_talkers()
        self.top_table.setRowCount(len(rows))
        for i, (host, byt, pkts) in enumerate(rows):
            self.top_table.setItem(i, 0, QtWidgets.QTableWidgetItem(str(host)))
            self.top_table.setItem(i, 1, QtWidgets.QTableWidgetItem(f"{byt:,}"))
            self.top_table.setItem(i, 2, QtWidgets.QTableWidgetItem(f"{pkts:,}"))

    def _update_stats_label(self):
        times, bins = self.agg.get_recent_bins()
        if not bins:
            return
        last = bins[-1]
        lines = [
            f"Current 1s bin → pkts={last['pkts']} bytes={last['bytes']} tcp={last['tcp']} udp={last['udp']} syn={last['syn']} dns={last['dns']}",
            f"Unique srcs (bin)={last['unique_srcs']}  Unique dsts (bin)={last['unique_dsts']}",
            f"Baseline windows: {len(self.model.X_baseline)}  Model ready: {self.model.ready()}",
        ]
        self.stats_label.setText("\n".join(lines))

    def _append_anomaly(self, severity, typ, detail):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.anomaly_rows.append((ts, severity, typ, detail))
        row = self.anom_table.rowCount()
        self.anom_table.insertRow(row)
        self.anom_table.setItem(row, 0, QtWidgets.QTableWidgetItem(ts))
        sev_item = QtWidgets.QTableWidgetItem(severity)
        if severity == "HIGH":
            sev_item.setForeground(QtGui.QBrush(Qt.red))
        elif severity == "MED":
            sev_item.setForeground(QtGui.QBrush(QtGui.QColor(200,120,0)))
        else:
            sev_item.setForeground(QtGui.QBrush(Qt.darkYellow))
        self.anom_table.setItem(row, 1, sev_item)
        self.anom_table.setItem(row, 2, QtWidgets.QTableWidgetItem(typ))
        self.anom_table.setItem(row, 3, QtWidgets.QTableWidgetItem(detail))
        self.anom_table.scrollToBottom()

    def export_anomalies(self):
        if not self.anomaly_rows:
            QtWidgets.QMessageBox.information(self, "Nothing to export", "No anomalies recorded yet.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save CSV", "anomalies.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["time","severity","type","details"])
                w.writerows(self.anomaly_rows)
            QtWidgets.QMessageBox.information(self, "Saved", f"Anomalies exported to {os.path.basename(path)}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Export Error", str(e))

    def save_charts(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Charts", "charts.png", "PNG (*.png)")
        if not path:
            return
        try:
            # save both charts stacked
            fig = Figure(figsize=(8,6), dpi=120)
            ax1 = fig.add_subplot(211)
            ax2 = fig.add_subplot(212)

            # replicate data
            _, bins = self.agg.get_recent_bins()
            y = [b['pkts'] for b in bins]
            ax1.plot(range(len(y)), y)
            ax1.set_title("Packets / second")
            ax1.set_xlabel("Recent seconds")
            ax1.set_ylabel("Packets")

            tcp = sum(b['tcp'] for b in bins)
            udp = sum(b['udp'] for b in bins)
            other = sum(b['other'] for b in bins)
            ax2.bar(["TCP","UDP","Other"], [tcp,udp,other])
            ax2.set_title("Protocol Mix (window)")
            ax2.set_ylabel("Count")

            fig.tight_layout()
            fig.savefig(path)
            QtWidgets.QMessageBox.information(self, "Saved", f"Charts saved to {os.path.basename(path)}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save Error", str(e))

# ----------------------------- Main ------------------------------------------

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = NetVizApp()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
