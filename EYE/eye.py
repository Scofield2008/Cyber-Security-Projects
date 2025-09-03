# eye_v2.py
"""
EYE v2 - Focused Website Vulnerability Scanner (Safe, Permissioned, GUI)
- PyQt5 GUI
- Multithreaded scanning
- Severity levels, remediation guidance
- Export to TXT/HTML
- Rate-limited, non-exploitative probes only

Usage: python eye_v2.py
"""

import sys
import re
import random
import string
import time
import requests
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode
from bs4 import BeautifulSoup
from datetime import datetime
from html import escape

from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QProgressBar, QTabWidget, QCheckBox, QSpinBox, QMessageBox, QFileDialog,
    QFormLayout, QGroupBox, QComboBox
)

# --- Config & patterns ---
SQL_ERROR_SIGNALS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"pg_query\(",
    r"SQLite\/JDBCDriver",
    r"ORA-00933",
    r"SQLSTATE",
    r"syntax error at or near",
]
DB_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNALS), re.IGNORECASE)

DEFAULT_HEADERS = {
    "User-Agent": "EYE-Scanner/2.0 (+https://example.com/eye)"
}

COMMON_ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/login", "/manage", "/console", "/admin.php"]

XSS_PAYLOADS = ["EYEREF-{}"]
SQL_PAYLOADS = ["'", "\"", "' OR '1'='1"]

# Remediation tips map
REMEDIATION = {
    "Missing Security Header": "Add recommended header (HSTS, CSP, X-Frame-Options, etc.) and set secure values.",
    "Server Header Disclosure": "Avoid exposing product and version in Server header; return a generic value or remove.",
    "Possible Reflected Input": "Output-encode user-supplied data, implement CSP, validate input server-side.",
    "Possible SQL Error Disclosure": "Use parameterized queries / ORMs. Do not display DB errors to users.",
    "Directory Listing": "Disable directory listing in the server configuration (e.g., Options -Indexes).",
    "Common Path Discovery": "Protect admin endpoints with strong authentication and network restrictions."
}

# --- Helpers ---
def random_token(n=12):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def now_ts():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# --- Result object ---
class Finding:
    def __init__(self, severity, kind, url, evidence, recommendation):
        self.severity = severity  # CRITICAL / HIGH / MEDIUM / LOW
        self.kind = kind
        self.url = url
        self.evidence = evidence
        self.recommendation = recommendation
        self.time = now_ts()

    def to_text(self):
        return f"[{self.severity}] {self.kind} @ {self.url}\nEvidence: {self.evidence}\nRemediation: {self.recommendation}\nTime: {self.time}\n"

    def to_html(self):
        return f"<div class='finding'><h3>[{escape(self.severity)}] {escape(self.kind)}</h3><p><strong>URL:</strong> {escape(self.url)}</p><p><strong>Evidence:</strong> {escape(self.evidence)}</p><p><strong>Remediation:</strong> {escape(self.recommendation)}</p><p><em>{escape(self.time)}</em></p></div>"

# --- Scanner thread ---
class ScannerThread(QThread):
    progress = pyqtSignal(str, int)  # message, percent
    finished_signal = pyqtSignal(list)  # list of Finding

    def __init__(self, target, opts):
        super().__init__()
        self.target = target.rstrip("/")
        self.opts = opts
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.stopped = False

    def stop(self):
        self.stopped = True

    def safe_get(self, url, method="GET", **kwargs):
        """Wrapper for safe get/head with rate limiting and exception handling."""
        if self.stopped:
            raise RuntimeError("Scan stopped")
        time.sleep(self.opts['delay'])
        try:
            if method == "HEAD":
                return self.session.head(url, timeout=self.opts['timeout'], allow_redirects=True, verify=True)
            else:
                return self.session.get(url, timeout=self.opts['timeout'], allow_redirects=True, verify=True)
        except requests.RequestException as e:
            return None

    def emit_progress(self, text, pct=None):
        if pct is None:
            pct = 0
        self.progress.emit(text, pct)

    def run(self):
        findings = []
        try:
            # 0% - start
            self.emit_progress("Starting scan...", 1)

            # Check root reachable
            self.emit_progress("Fetching target root...", 5)
            r = self.safe_get(self.target)
            if not r:
                self.emit_progress("Failed to fetch target root (network/timeout).", 100)
                self.finished_signal.emit(findings)
                return

            # Fingerprint
            server_hdr = r.headers.get("Server")
            powered_by = r.headers.get("X-Powered-By")
            techs = []
            if server_hdr:
                techs.append(f"Server: {server_hdr}")
                findings.append(Finding("LOW", "Server Header Disclosure", self.target, f"Server header: {server_hdr}", REMEDIATION.get("Server Header Disclosure")))
            if powered_by:
                techs.append(f"X-Powered-By: {powered_by}")
                findings.append(Finding("LOW", "Information Disclosure", self.target, f"X-Powered-By: {powered_by}", "Remove X-Powered-By headers and hide stack traces."))

            self.emit_progress(f"Fingerprint: {', '.join(techs) or 'unknown'}", 8)

            # Security headers check
            self.emit_progress("Checking security headers...", 12)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            expected = {
                "strict-transport-security": "Enable HSTS for HTTPS responses (set max-age, includeSubDomains).",
                "content-security-policy": "Implement a restrictive CSP to reduce XSS impact and block inline scripts.",
                "x-frame-options": "Set X-Frame-Options (DENY or SAMEORIGIN) to prevent clickjacking.",
                "x-content-type-options": "Set X-Content-Type-Options: nosniff to prevent content sniffing.",
                "referrer-policy": "Set a secure Referrer-Policy (no-referrer or same-origin)."
            }
            for h, rec in expected.items():
                if h not in headers_lower:
                    findings.append(Finding("MEDIUM", "Missing Security Header", self.target, f"{h} missing", rec))
            self.emit_progress("Security headers checked.", 18)

            # robots.txt & directory listing
            self.emit_progress("Checking robots.txt and directory listing...", 22)
            p = urlparse(self.target)
            robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
            r_robots = self.safe_get(robots_url)
            if r_robots and r_robots.status_code == 200 and "Disallow" in (r_robots.text or ""):
                findings.append(Finding("LOW", "Robots.txt present", robots_url, "robots.txt present; check it doesn't list sensitive paths.", "Avoid listing sensitive paths in robots.txt."))
            # directory listing check
            if r and "Index of /" in (r.text or ""):
                findings.append(Finding("MEDIUM", "Directory Listing", self.target, "Response contains 'Index of /' likely directory listing", REMEDIATION.get("Directory Listing")))
            self.emit_progress("Robots and index checked.", 26)

            # Crawl links and forms (limited)
            self.emit_progress("Crawling links and forms (limited)...", 30)
            links, forms = self.discover_links_and_forms(self.target, max_pages=self.opts['max_pages'])
            self.emit_progress(f"Found {len(links)} links, {len(forms)} forms", 36)

            # Common admin paths (HEAD requests)
            if self.opts['check_common_paths']:
                self.emit_progress("Checking common admin paths (read-only)...", 40)
                for i, ppath in enumerate(COMMON_ADMIN_PATHS):
                    test = urljoin(self.target + "/", ppath.lstrip("/"))
                    hr = self.safe_get(test, method="HEAD")
                    if hr and hr.status_code in (200, 401, 403, 302):
                        sev = "MEDIUM" if hr.status_code == 200 else "LOW"
                        findings.append(Finding(sev, "Common Path Discovery", test, f"Status code {hr.status_code}", REMEDIATION.get("Common Path Discovery")))
                    # update progress
                    pct = 40 + int((i+1) * 5 / len(COMMON_ADMIN_PATHS))
                    self.emit_progress(f"Checked {ppath} -> {hr.status_code if hr else 'no response'}", pct)

            # Parameter reflection checks (XSS indicator) - non-exploitative: send harmless token
            if self.opts['check_xss']:
                self.emit_progress("Testing for reflected input (XSS indicator)...", 55)
                checked = 0
                for link in links[:self.opts['max_pages']]:
                    if checked >= self.opts['max_params']:
                        break
                    qs = dict(parse_qsl(urlparse(link).query))
                    for p in qs:
                        if checked >= self.opts['max_params']:
                            break
                        token = "EYEREF-" + random_token(8)
                        qdict = dict(qs)
                        qdict[p] = token
                        test_url = link.split("?")[0] + "?" + urlencode(qdict)
                        rtest = self.safe_get(test_url)
                        if rtest and token in (rtest.text or ""):
                            findings.append(Finding("HIGH", "Possible Reflected Input (XSS indicator)", test_url, f"Token {token} reflected in response", REMEDIATION.get("Possible Reflected Input", "Sanitize/encode output; implement CSP.")))
                        checked += 1
                        self.emit_progress(f"Reflection test on {p} of {link}", 55 + int(10 * checked / self.opts['max_params']))
                self.emit_progress("Reflection checks done.", 66)

            # SQL error heuristics (non-exploitative): send single-quote to param and look for DB error hints
            if self.opts['check_sqli']:
                self.emit_progress("Testing for SQL error disclosures...", 68)
                checked = 0
                for link in links[:self.opts['max_pages']]:
                    if checked >= self.opts['max_params']:
                        break
                    qs = dict(parse_qsl(urlparse(link).query))
                    for p in qs:
                        if checked >= self.opts['max_params']:
                            break
                        qdict = dict(qs)
                        qdict[p] = "'"
                        test_url = link.split("?")[0] + "?" + urlencode(qdict)
                        rtest = self.safe_get(test_url)
                        if rtest and DB_ERROR_RE.search(rtest.text or ""):
                            snippet = (rtest.text or "")[:400]
                            findings.append(Finding("CRITICAL", "Possible SQL Error Disclosure", test_url, f"DB-like text detected: {snippet}", REMEDIATION.get("Possible SQL Error Disclosure")))
                        checked += 1
                        self.emit_progress(f"SQLi heuristic on {p} of {link}", 68 + int(10 * checked / self.opts['max_params']))
                self.emit_progress("SQL heuristics done.", 80)

            # Forms: check for reflected form inputs
            if forms and self.opts['check_forms']:
                self.emit_progress("Checking form inputs (reflection heuristics)...", 82)
                fchecked = 0
                for form in forms[:self.opts['max_forms']]:
                    for inp in form['inputs']:
                        if fchecked >= self.opts['max_forms'] * 3:
                            break
                        name = inp['name']
                        token = "EYEREF-" + random_token(6)
                        fake_url = form['action'] + "?" + urlencode({name: token})
                        rtest = self.safe_get(fake_url)
                        if rtest and token in (rtest.text or ""):
                            findings.append(Finding("HIGH", "Possible Reflected Form Input", fake_url, "Reflected token seen in form response", REMEDIATION.get("Possible Reflected Input", "Sanitize and encode inputs.")))
                        fchecked += 1
                        self.emit_progress(f"Form reflection check {name} -> {form['action']}", 82 + int(10 * fchecked / (self.opts['max_forms'] * 3)))
                self.emit_progress("Form checks done.", 88)

            self.emit_progress("Finalizing findings...", 94)
            # If no findings, add a low severity note
            if not findings:
                findings.append(Finding("LOW", "No high-confidence issues detected", self.target, "No indicators found by this focused scan", "Consider a deeper authorized pentest for full verification."))

            self.emit_progress("Scan finished.", 100)
            self.finished_signal.emit(findings)

        except Exception as e:
            self.emit_progress(f"Scan aborted: {e}", 100)
            self.finished_signal.emit(findings)

    def discover_links_and_forms(self, base_url, max_pages=30):
        """Simple crawler: fetch base_url, parse links and simple forms (non-js)."""
        try:
            r = self.safe_get(base_url)
            if not r:
                return [], []
            soup = BeautifulSoup(r.text or "", "html.parser")
            links = set()
            forms = []
            origin = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(base_url))
            for a in soup.find_all("a", href=True):
                href = a.get("href").strip()
                full = urljoin(base_url, href)
                if urlparse(full).scheme in ("http", "https"):
                    if urlparse(full).netloc == urlparse(base_url).netloc:
                        links.add(full)
            for f in soup.find_all("form"):
                action = f.get("action") or base_url
                method = f.get("method", "get").lower()
                inputs = []
                for inp in f.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    itype = inp.get("type", "text")
                    inputs.append({"name": name, "type": itype})
                forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})
            return list(links)[:max_pages], forms[:max_pages]
        except Exception:
            return [], []

# --- GUI Application ---
class EyeApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EYE v2 - Focused Website Vulnerability Scanner")
        self.setGeometry(200, 200, 900, 650)
        self.scanner_thread = None
        self.findings = []

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        # Tabs
        self.tabs = QTabWidget()
        self.tab_scan = QWidget()
        self.tab_settings = QWidget()
        self.tab_reports = QWidget()

        self.tabs.addTab(self.tab_scan, "Scanner")
        self.tabs.addTab(self.tab_settings, "Settings")
        self.tabs.addTab(self.tab_reports, "Reports")

        self._build_scan_tab()
        self._build_settings_tab()
        self._build_reports_tab()

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def _build_scan_tab(self):
        v = QVBoxLayout()

        # Target input + permission checkbox
        h1 = QHBoxLayout()
        self.input_url = QLineEdit()
        self.input_url.setPlaceholderText("https://example.com (must include scheme)")
        h1.addWidget(QLabel("Target URL:"))
        h1.addWidget(self.input_url)
        v.addLayout(h1)

        self.permission_checkbox = QCheckBox("I confirm I have explicit written permission to scan this target (required)")
        v.addWidget(self.permission_checkbox)

        # Buttons
        h2 = QHBoxLayout()
        self.btn_start = QPushButton("Start Scan")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("Stop Scan")
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setEnabled(False)
        h2.addWidget(self.btn_start)
        h2.addWidget(self.btn_stop)
        v.addLayout(h2)

        # Progress and output
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        v.addWidget(self.progress_bar)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        v.addWidget(self.output_area)

        self.tab_scan.setLayout(v)

    def _build_settings_tab(self):
        v = QVBoxLayout()

        form = QFormLayout()
        # Timeout
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(1, 60)
        self.spin_timeout.setValue(7)
        form.addRow("Request timeout (s):", self.spin_timeout)

        # Delay / rate limit
        self.spin_delay = QSpinBox()
        self.spin_delay.setRange(0, 10)
        self.spin_delay.setValue(1)
        form.addRow("Delay between requests (s):", self.spin_delay)

        # Max pages and params
        self.spin_max_pages = QSpinBox()
        self.spin_max_pages.setRange(1, 200)
        self.spin_max_pages.setValue(20)
        form.addRow("Max pages to crawl:", self.spin_max_pages)

        self.spin_max_params = QSpinBox()
        self.spin_max_params.setRange(1, 200)
        self.spin_max_params.setValue(40)
        form.addRow("Max parameters to test:", self.spin_max_params)

        # Options checkboxes
        box = QGroupBox("Checks")
        box_layout = QVBoxLayout()
        self.chk_headers = QCheckBox("Security headers")
        self.chk_headers.setChecked(True)
        self.chk_xss = QCheckBox("Reflection (XSS indicator)")
        self.chk_xss.setChecked(True)
        self.chk_sqli = QCheckBox("SQL error signals")
        self.chk_sqli.setChecked(True)
        self.chk_common = QCheckBox("Common paths discovery")
        self.chk_common.setChecked(True)
        self.chk_forms = QCheckBox("Form input checks")
        self.chk_forms.setChecked(True)
        box_layout.addWidget(self.chk_headers)
        box_layout.addWidget(self.chk_xss)
        box_layout.addWidget(self.chk_sqli)
        box_layout.addWidget(self.chk_forms)
        box_layout.addWidget(self.chk_common)
        box.setLayout(box_layout)

        v.addLayout(form)
        v.addWidget(box)
        note = QLabel("Disclaimer: EYE performs only non-exploitative probes. Always scan only with permission.")
        note.setWordWrap(True)
        v.addWidget(note)

        self.tab_settings.setLayout(v)

    def _build_reports_tab(self):
        v = QVBoxLayout()
        self.reports_text = QTextEdit()
        self.reports_text.setReadOnly(True)
        v.addWidget(self.reports_text)
        h = QHBoxLayout()
        self.btn_save_txt = QPushButton("Save Report (TXT)")
        self.btn_save_txt.clicked.connect(self.save_txt)
        self.btn_save_html = QPushButton("Save Report (HTML)")
        self.btn_save_html.clicked.connect(self.save_html)
        h.addWidget(self.btn_save_txt)
        h.addWidget(self.btn_save_html)
        v.addLayout(h)
        self.tab_reports.setLayout(v)

    def start_scan(self):
        url = self.input_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing URL", "Please enter a target URL (include http(s)://).")
            return
        if not self.permission_checkbox.isChecked():
            QMessageBox.warning(self, "Permission Required", "You must confirm you have written permission to scan this target.")
            return

        # collect options
        opts = {
            'timeout': int(self.spin_timeout.value()),
            'delay': float(self.spin_delay.value()),
            'max_pages': int(self.spin_max_pages.value()),
            'max_params': int(self.spin_max_params.value()),
            'max_forms': 30,
            'check_xss': self.chk_xss.isChecked(),
            'check_sqli': self.chk_sqli.isChecked(),
            'check_headers': self.chk_headers.isChecked(),
            'check_common_paths': self.chk_common.isChecked(),
            'check_forms': self.chk_forms.isChecked()
        }

        # disable start, enable stop
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.output_area.clear()
        self.progress_bar.setValue(0)
        self.findings = []

        # create and start scanner thread
        self.scanner_thread = ScannerThread(url, opts)
        self.scanner_thread.progress.connect(self.on_progress)
        self.scanner_thread.finished_signal.connect(self.on_finished)
        self.scanner_thread.start()

    def stop_scan(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.output_area.append("Stopping scan...")
            self.btn_stop.setEnabled(False)

    def on_progress(self, text, pct):
        self.output_area.append(f"[{now_ts()}] {text}")
        self.progress_bar.setValue(min(max(int(pct), 0), 100))

    def on_finished(self, findings):
        self.findings = findings
        self.output_area.append("\n--- Scan finished ---\n")
        # Render findings into output and reports tab
        text = []
        html_fragments = []
        for f in findings:
            self.output_area.append(f.to_text())
            text.append(f.to_text())
            html_fragments.append(f.to_html())
        self.reports_text.setHtml("<h2>EYE v2 Scan Report</h2>" + "\n".join(html_fragments))
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setValue(100)

    def format_report_text(self):
        header = f"EYE v2 Scan Report\nTarget: {self.input_url.text().strip()}\nTime: {now_ts()}\n\n"
        body = "\n".join([f.to_text() for f in self.findings])
        return header + body

    def format_report_html(self):
        header = f"<h1>EYE v2 Scan Report</h1><p><strong>Target:</strong> {escape(self.input_url.text().strip())}</p><p><em>{escape(now_ts())}</em></p>"
        body = "\n".join([f.to_html() for f in self.findings])
        full = f"""<html><head><meta charset="utf-8"><style>
        body{{font-family:Arial,Helvetica,sans-serif; padding:20px}}
        .finding{{border:1px solid #ddd;padding:10px;margin:10px 0;border-radius:6px}}
        h3{{margin:0 0 6px 0}}
        </style></head><body>{header}{body}</body></html>"""
        return full

    def save_txt(self):
        if not self.findings:
            QMessageBox.information(self, "No report", "No findings to save. Run a scan first.")
            return
        fname, _ = QFileDialog.getSaveFileName(self, "Save report as TXT", "eye_report.txt", "Text Files (*.txt)")
        if not fname:
            return
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.format_report_text())
            QMessageBox.information(self, "Saved", f"Report saved to {fname}")
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))

    def save_html(self):
        if not self.findings:
            QMessageBox.information(self, "No report", "No findings to save. Run a scan first.")
            return
        fname, _ = QFileDialog.getSaveFileName(self, "Save report as HTML", "eye_report.html", "HTML Files (*.html *.htm)")
        if not fname:
            return
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.format_report_html())
            QMessageBox.information(self, "Saved", f"Report saved to {fname}")
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))

# --- Run app ---
def main():
    app = QApplication(sys.argv)
    window = EyeApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
