"""
TorShield — System-Wide Tor VPN  (PyQt-Fluent-Widgets edition, v2.2)
====================================================================
Premium Fluent UI: soft shadows, a monochromatic palette and subtle
micro-interactions. The activity terminal uses a soft, translucent (non-black)
surface; the whole layout is fully scalable for full-screen or small windows.

System-wide routing is AUTOMATIC on connect (no switch) — each step is shown
in the terminal. obfs4 + snowflake bridges are fetched automatically from Tor's
BridgeDB, and the app checks GitHub for updates and offers to update in place.

All backend logic lives in torshield_core. This file is the view layer only.
"""

import os
import sys
import threading


def _windows_no_console() -> None:
    """
    Windows: make sure no black cmd window is ever shown. If we are running under
    the console python.exe, re-launch the exact same script under pythonw.exe
    (which is windowless) and exit, so the console disappears immediately. Under
    pythonw there is no stdout/stderr, so point them at the null device to keep any
    stray print() safe. Completely no-op on Linux.
    """
    if os.name != "nt":
        return
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        return            # a built exe (PyInstaller/Nuitka, windowed) has no console
    exe = sys.executable or ""
    already_windowless = (exe.lower().endswith("pythonw.exe")
                          or os.environ.get("TORSHIELD_PYW") == "1")
    if already_windowless:
        for _name in ("stdout", "stderr"):
            if getattr(sys, _name, None) is None:
                try:
                    setattr(sys, _name, open(os.devnull, "w"))
                except Exception:
                    pass
        return
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if not os.path.isfile(pyw):
        return                      # no pythonw — fall back to the normal console
    try:
        import subprocess
        subprocess.Popen(
            [pyw, os.path.abspath(__file__)] + sys.argv[1:],
            env=dict(os.environ, TORSHIELD_PYW="1"),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            close_fds=True)
    except Exception:
        return                      # couldn't relaunch — keep running as-is
    sys.exit(0)


_windows_no_console()


def _add_invoking_user_site_packages() -> None:
    """
    The app runs as ROOT (via pkexec/sudo), but its pip dependencies
    (qfluentwidgets, stem, requests…) are usually installed into the *normal*
    user's ~/.local. Root's Python does not look there, so add that path before
    importing anything. Covers `sudo` (SUDO_USER), `pkexec` (PKEXEC_UID), and a
    HOME passed through by the launcher.
    """
    homes = []
    su = os.environ.get("SUDO_USER")
    if su:
        try:
            import pwd
            homes.append(pwd.getpwnam(su).pw_dir)
        except Exception:
            homes.append(os.path.expanduser("~" + su))
    pk = os.environ.get("PKEXEC_UID")
    if pk:
        try:
            import pwd
            homes.append(pwd.getpwuid(int(pk)).pw_dir)
        except Exception:
            pass
    h = os.environ.get("HOME")
    if h:
        homes.append(h)
    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    seen = set()
    for home in homes:
        if not home or home in seen or home == "/root":
            continue
        seen.add(home)
        sp = os.path.join(home, ".local", "lib", ver, "site-packages")
        if os.path.isdir(sp) and sp not in sys.path:
            sys.path.insert(0, sp)


_add_invoking_user_site_packages()

# Backend (framework-agnostic). Elevate before building any UI.
try:
    import torshield_core as core
except Exception:
    # Allow running from the install dir where core sits next to this file.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import torshield_core as core

core.ensure_root()

from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont, QIcon, QPixmap, QTextCursor
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QSplitter,
    QSizePolicy, QGraphicsDropShadowEffect, QScrollArea, QFrame, QSpacerItem)

from qfluentwidgets import (
    setTheme, Theme, setThemeColor, PrimaryPushButton, PushButton, ComboBox,
    TextEdit, ProgressBar, BodyLabel, StrongBodyLabel, TitleLabel, SubtitleLabel,
    CaptionLabel, CardWidget, InfoBar, InfoBarPosition, MessageBox, FluentIcon)


# ─────────────────────────────────────────────────────────────────────────────
# Premium dark palette — deep neutrals + one vivid violet accent
# ─────────────────────────────────────────────────────────────────────────────
ACCENT      = "#9B7DFF"   # vivid violet accent
ACCENT_SOFT = "#3A2E6B"   # accent tint for fills/pills
BG          = "#08080C"   # app background (near-black, soft)
SURFACE     = "#13131B"   # cards
SURFACE_2   = "#1B1B27"   # raised inputs / hover
STROKE      = "#272735"   # hairline borders
TERMINAL_BG = "#0C0C13"   # terminal: deep but NOT pure black
TEXT        = "#F3F3F8"
SUBTEXT     = "#A0A0B4"
MUTED       = "#5C5C70"
OK          = "#5CE6A8"
WARN        = "#FFC56E"
ERR         = "#FF6B7E"
ENTRY       = "#5CE6A8"
MIDDLE      = "#FFC56E"
EXIT        = "#FF6B7E"

MONO = "JetBrains Mono, Fira Code, DejaVu Sans Mono, Consolas, monospace"

# Complete ISO 3166-1 alpha-2 → country name. Any exit node resolves to a name;
# anything not here (rare/none) falls back to the raw code.
COUNTRY_NAMES = {
    "AF": "Afghanistan", "AX": "Åland Islands", "AL": "Albania", "DZ": "Algeria",
    "AS": "American Samoa", "AD": "Andorra", "AO": "Angola", "AI": "Anguilla",
    "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina",
    "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria",
    "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh",
    "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize",
    "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia",
    "BQ": "Caribbean Netherlands", "BA": "Bosnia and Herzegovina", "BW": "Botswana",
    "BV": "Bouvet Island", "BR": "Brazil", "IO": "British Indian Ocean Territory",
    "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
    "CV": "Cabo Verde", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
    "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad",
    "CL": "Chile", "CN": "China", "CX": "Christmas Island", "CC": "Cocos Islands",
    "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "DR Congo",
    "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Côte d'Ivoire", "HR": "Croatia",
    "CU": "Cuba", "CW": "Curaçao", "CY": "Cyprus", "CZ": "Czechia",
    "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic",
    "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea",
    "ER": "Eritrea", "EE": "Estonia", "SZ": "Eswatini", "ET": "Ethiopia",
    "FK": "Falkland Islands", "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland",
    "FR": "France", "GF": "French Guiana", "PF": "French Polynesia",
    "TF": "French Southern Territories", "GA": "Gabon", "GM": "Gambia",
    "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar",
    "GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe",
    "GU": "Guam", "GT": "Guatemala", "GG": "Guernsey", "GN": "Guinea",
    "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti",
    "HM": "Heard & McDonald Islands", "VA": "Vatican City", "HN": "Honduras",
    "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India",
    "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland",
    "IM": "Isle of Man", "IL": "Israel", "IT": "Italy", "JM": "Jamaica",
    "JP": "Japan", "JE": "Jersey", "JO": "Jordan", "KZ": "Kazakhstan",
    "KE": "Kenya", "KI": "Kiribati", "KP": "North Korea", "KR": "South Korea",
    "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Laos", "LV": "Latvia",
    "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libya",
    "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macau",
    "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives",
    "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique",
    "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico",
    "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia",
    "ME": "Montenegro", "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique",
    "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru", "NP": "Nepal",
    "NL": "Netherlands", "NC": "New Caledonia", "NZ": "New Zealand",
    "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "NU": "Niue",
    "NF": "Norfolk Island", "MK": "North Macedonia", "MP": "Northern Mariana Islands",
    "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau",
    "PS": "Palestine", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay",
    "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn Islands", "PL": "Poland",
    "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RE": "Réunion",
    "RO": "Romania", "RU": "Russia", "RW": "Rwanda", "BL": "Saint Barthélemy",
    "SH": "Saint Helena", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
    "MF": "Saint Martin", "PM": "Saint Pierre and Miquelon",
    "VC": "Saint Vincent", "WS": "Samoa", "SM": "San Marino",
    "ST": "São Tomé and Príncipe", "SA": "Saudi Arabia", "SN": "Senegal",
    "RS": "Serbia", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
    "SX": "Sint Maarten", "SK": "Slovakia", "SI": "Slovenia",
    "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
    "GS": "South Georgia", "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka",
    "SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard and Jan Mayen",
    "SE": "Sweden", "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan",
    "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand", "TL": "Timor-Leste",
    "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago",
    "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan",
    "TC": "Turks and Caicos Islands", "TV": "Tuvalu", "UG": "Uganda",
    "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom",
    "US": "United States", "UM": "U.S. Minor Outlying Islands", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam",
    "VG": "British Virgin Islands", "VI": "U.S. Virgin Islands",
    "WF": "Wallis and Futuna", "EH": "Western Sahara", "YE": "Yemen",
    "ZM": "Zambia", "ZW": "Zimbabwe",
}

CARD_QSS = (f"CardWidget {{ background: {SURFACE}; border: 1px solid {STROKE};"
            f" border-radius: 14px; }}")


def soft_shadow(widget, blur=26, dy=6, alpha=70):
    """Subtle drop shadow for a gently lifted, premium look (not heavy)."""
    eff = QGraphicsDropShadowEffect(widget)
    eff.setBlurRadius(blur)
    eff.setXOffset(0)
    eff.setYOffset(dy)
    eff.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(eff)


class TorShieldWindow(QWidget):
    # Signals marshal worker-thread updates onto the GUI thread safely.
    sig_log          = pyqtSignal(str, str)
    sig_status       = pyqtSignal(str)
    sig_progress     = pyqtSignal(int, str)
    sig_circuits     = pyqtSignal(list)
    sig_ip           = pyqtSignal(str, str)
    sig_bridges      = pyqtSignal(str, str)
    sig_update       = pyqtSignal(dict)
    sig_info         = pyqtSignal(str, str, str)   # title, msg, level

    def __init__(self):
        super().__init__()
        self._tor = core.TorManager()
        self._status = "disconnected"
        self._routing_active = False
        self._connect_secs = 0
        self._cancel = threading.Event()   # set to abort an in-progress connect

        # Safety net: restore routing/DNS on ANY interpreter exit (unhandled
        # exception, normal quit) — not just the window-close handler — so the user
        # is never left offline. Combined with the startup auto-repair, the only
        # way to stay stuck is a hard kill, which `reset_internet.bat` undoes.
        import atexit
        atexit.register(self._emergency_restore)

        self.setWindowTitle(f"TorShield · System-Wide Tor VPN  v{core.__version__}")
        self.resize(1120, 780)
        self.setMinimumSize(720, 560)
        self.setStyleSheet(f"TorShieldWindow {{ background: {BG}; }}")

        self._load_window_icon()
        self._build_ui()
        self._connect_signals()

        self._uptime_timer = QTimer(self)
        self._uptime_timer.timeout.connect(self._tick_uptime)

        self._log_environment()

        # Background: check GitHub for updates; make sure Tor itself is present
        # (Windows downloads the Tor Expert Bundle on first run, so the user does
        # NOT need Tor Browser), then prefetch bridges.
        threading.Thread(target=self._check_updates, daemon=True).start()
        threading.Thread(target=self._startup_tor_and_bridges, daemon=True).start()

    # ── Icon ──────────────────────────────────────────────────────────────────
    def _logo_path(self):
        # Look in the PyInstaller bundle dir first (frozen exe), then the source dir.
        bases = []
        if getattr(sys, "frozen", False):
            bases.append(getattr(sys, "_MEIPASS", ""))
        bases.append(os.path.dirname(os.path.abspath(__file__)))
        for here in bases:
            for n in ("Header_Logo.png", "torshield.png"):
                p = os.path.join(here, n)
                if here and os.path.isfile(p):
                    return p
        return None

    def _load_window_icon(self):
        p = self._logo_path()
        if not p:
            return
        pix = QPixmap(p)
        if pix.isNull():
            return
        if pix.width() != pix.height():          # pad to square — no stretching
            side = max(pix.width(), pix.height())
            square = QPixmap(side, side)
            square.fill(Qt.transparent)
            from PyQt5.QtGui import QPainter
            painter = QPainter(square)
            painter.drawPixmap((side - pix.width()) // 2,
                               (side - pix.height()) // 2, pix)
            painter.end()
            pix = square
        self.setWindowIcon(QIcon(pix))

    # ── Theme + layout ─────────────────────────────────────────────────────────
    def _build_ui(self):
        setTheme(Theme.DARK)
        setThemeColor(ACCENT)
        self.setStyleSheet(f"""
            TorShieldWindow {{ background: {BG}; }}
            QScrollBar:vertical {{ background: transparent; width: 9px; margin: 2px; }}
            QScrollBar::handle:vertical {{ background: {STROKE}; border-radius: 4px; min-height: 30px; }}
            QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
            QScrollBar::add-line, QScrollBar::sub-line {{ height: 0px; }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 20)
        root.setSpacing(16)

        root.addWidget(self._build_header())

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(12)
        splitter.addWidget(self._build_left())
        splitter.addWidget(self._build_right())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([390, 730])
        root.addWidget(splitter, 1)

    def _build_header(self):
        card = CardWidget(self)
        card.setFixedHeight(82)
        card.setStyleSheet(CARD_QSS)
        soft_shadow(card, blur=24, dy=6, alpha=60)
        lay = QHBoxLayout(card)
        lay.setContentsMargins(24, 12, 20, 12)
        lay.setSpacing(16)

        logo = self._logo_path()
        if logo:
            from qfluentwidgets import ImageLabel
            try:
                img = ImageLabel(logo, card)
                img.setFixedSize(46, 46)
                img.setBorderRadius(12, 12, 12, 12)
                lay.addWidget(img)
            except Exception:
                pass

        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        t = StrongBodyLabel("TorShield", card)
        t.setStyleSheet(f"color: {TEXT}; font-size: 24px; font-weight: 800; letter-spacing: 0.3px;")
        sub = CaptionLabel("System-Wide Tor VPN", card)
        sub.setStyleSheet(f"color: {SUBTEXT}; font-size: 12px;")
        title_box.addWidget(t)
        title_box.addWidget(sub)
        lay.addLayout(title_box)
        lay.addStretch(1)

        self._status_chip = StrongBodyLabel("DISCONNECTED", card)
        self._apply_chip(ERR)
        lay.addWidget(self._status_chip)
        return card

    def _apply_chip(self, color):
        """Pill-styled status badge with a soft tinted background."""
        self._status_chip.setStyleSheet(
            f"StrongBodyLabel {{ color: {color}; font-size: 13px; font-weight: 800;"
            f" letter-spacing: 1px; padding: 7px 16px;"
            f" background: rgba(255,255,255,0.04);"
            f" border: 1px solid {color}; border-radius: 14px; }}")

    def _section(self, parent_layout, text):
        lbl = CaptionLabel(text.upper())
        lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 11px; font-weight: 800; "
            "letter-spacing: 1.4px; margin-top: 10px; margin-bottom: 2px;")
        parent_layout.addWidget(lbl)

    def _build_left(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        scroll.setMinimumWidth(330)

        panel = QWidget()
        panel.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(2, 2, 14, 4)
        lay.setSpacing(8)

        # Connect / disconnect
        self._section(lay, "Connection")
        self._connect_btn = PrimaryPushButton("Connect", panel, FluentIcon.PLAY)
        self._connect_btn.setFixedHeight(52)
        _bf = QFont(); _bf.setPointSize(13); _bf.setBold(True)
        self._connect_btn.setFont(_bf)   # font only — no stylesheet (keeps accent fill)
        self._connect_btn.clicked.connect(self._on_connect)
        lay.addWidget(self._connect_btn)
        self._disconnect_btn = PushButton("Disconnect", panel, FluentIcon.POWER_BUTTON)
        self._disconnect_btn.setFixedHeight(42)
        self._disconnect_btn.setEnabled(False)
        self._disconnect_btn.clicked.connect(self._on_disconnect)
        lay.addWidget(self._disconnect_btn)

        self._progress = ProgressBar(panel)
        self._progress.setValue(0)
        lay.addWidget(self._progress)
        self._progress_lbl = CaptionLabel("idle", panel)
        self._progress_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        lay.addWidget(self._progress_lbl)

        # Automatic bridges card
        self._section(lay, "Automatic Bridges")
        bcard = CardWidget(panel)
        bcard.setStyleSheet(CARD_QSS)
        soft_shadow(bcard, blur=20, dy=4, alpha=55)
        bl = QVBoxLayout(bcard)
        bl.setContentsMargins(16, 14, 16, 14)
        bl.setSpacing(10)
        info = BodyLabel(
            "Fully automatic: Direct → Snowflake → obfs4. Bridges are fetched "
            "from Tor's BridgeDB — nothing to configure.", bcard)
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {SUBTEXT}; font-size: 13px; line-height: 150%;")
        bl.addWidget(info)
        self._bridge_status = StrongBodyLabel("◌  bridges: checking…", bcard)
        self._bridge_status.setStyleSheet(f"color: {SUBTEXT}; font-size: 13px; font-weight: 700;")
        bl.addWidget(self._bridge_status)
        self._refresh_btn = PushButton("Refresh bridges from Tor", bcard, FluentIcon.SYNC)
        self._refresh_btn.setFixedHeight(38)
        self._refresh_btn.clicked.connect(self._on_refresh_bridges)
        bl.addWidget(self._refresh_btn)
        lay.addWidget(bcard)

        # Exit country
        self._section(lay, "Exit Node Country")
        self._country = ComboBox(panel)
        self._country.addItems(list(core.COUNTRY_CODES.keys()))
        self._country.setFixedHeight(40)
        self._country.currentTextChanged.connect(self._on_country_change)
        lay.addWidget(self._country)

        # Identity + test
        self._section(lay, "Identity & Test")
        self._newid_btn = PushButton("New Identity  ·  new circuit / IP", panel, FluentIcon.UPDATE)
        self._newid_btn.setFixedHeight(40)
        self._newid_btn.setEnabled(False)
        self._newid_btn.clicked.connect(self._on_new_identity)
        lay.addWidget(self._newid_btn)
        self._test_btn = PushButton("Test  ·  fetch Tor exit IP", panel, FluentIcon.SEARCH)
        self._test_btn.setFixedHeight(40)
        self._test_btn.setEnabled(False)
        self._test_btn.clicked.connect(self._on_test)
        lay.addWidget(self._test_btn)

        # Public IP
        self._section(lay, "Public IP via Tor")
        ipcard = CardWidget(panel)
        ipcard.setStyleSheet(CARD_QSS)
        soft_shadow(ipcard, blur=20, dy=4, alpha=55)
        il = QVBoxLayout(ipcard)
        il.setContentsMargins(16, 18, 16, 18)
        self._ip_lbl = SubtitleLabel("—", ipcard)
        self._ip_lbl.setAlignment(Qt.AlignCenter)
        self._ip_lbl.setStyleSheet(
            f"color: {OK}; font-size: 24px; font-weight: 800; font-family: {MONO};")
        il.addWidget(self._ip_lbl)
        lay.addWidget(ipcard)

        self._uptime_lbl = CaptionLabel("Uptime: —", panel)
        self._uptime_lbl.setStyleSheet(f"color: {SUBTEXT}; font-size: 12px; margin-top: 4px;")
        lay.addWidget(self._uptime_lbl)

        lay.addStretch(1)
        scroll.setWidget(panel)
        return scroll

    def _build_right(self):
        wrap = QWidget()
        wrap.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        # Circuits card
        ccard = CardWidget(wrap)
        ccard.setStyleSheet(CARD_QSS)
        soft_shadow(ccard, blur=24, dy=6, alpha=60)
        cl = QVBoxLayout(ccard)
        cl.setContentsMargins(18, 14, 18, 16)
        cl.setSpacing(10)
        chead = QHBoxLayout()
        chead.addWidget(self._mk_head("ACTIVE TOR CIRCUITS  ·  3-HOP PATH"))
        chead.addStretch(1)
        self._circ_ts = CaptionLabel("")
        self._circ_ts.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        chead.addWidget(self._circ_ts)
        cl.addLayout(chead)
        self._circuits = self._mk_terminal(min_h=270)
        cl.addWidget(self._circuits)
        lay.addWidget(ccard, 3)

        # Activity terminal card
        lcard = CardWidget(wrap)
        lcard.setStyleSheet(CARD_QSS)
        soft_shadow(lcard, blur=24, dy=6, alpha=60)
        ll = QVBoxLayout(lcard)
        ll.setContentsMargins(18, 14, 18, 16)
        ll.setSpacing(10)
        lhead = QHBoxLayout()
        lhead.addWidget(self._mk_head("ACTIVITY LOG  ·  TERMINAL"))
        lhead.addStretch(1)
        clear = PushButton("Clear")
        clear.setFixedHeight(30)
        clear.clicked.connect(lambda: self._log_term.clear())
        lhead.addWidget(clear)
        ll.addLayout(lhead)
        self._log_term = self._mk_terminal(min_h=220)
        ll.addWidget(self._log_term)
        lay.addWidget(lcard, 3)

        return wrap

    def _mk_head(self, text):
        lbl = CaptionLabel(text)
        lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 11px; font-weight: 800; letter-spacing: 1.4px;")
        return lbl

    def _mk_terminal(self, min_h=200):
        """Deep (non-black) terminal surface, hairline border, big mono font."""
        te = TextEdit()
        te.setReadOnly(True)
        te.setMinimumHeight(min_h)
        te.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        f = QFont("JetBrains Mono")
        f.setStyleHint(QFont.Monospace)
        f.setPointSize(12)
        te.setFont(f)
        te.document().setDocumentMargin(12)
        te.setStyleSheet(
            f"TextEdit {{ background: {TERMINAL_BG}; color: {TEXT};"
            f" border: 1px solid {STROKE}; border-radius: 12px;"
            f" selection-background-color: {ACCENT}; }}")
        return te

    # ── Signal wiring ───────────────────────────────────────────────────────────
    def _connect_signals(self):
        self.sig_log.connect(self._append_log)
        self.sig_status.connect(self._set_status)
        self.sig_progress.connect(self._set_progress)
        self.sig_circuits.connect(self._render_circuits)
        self.sig_ip.connect(self._set_ip)
        self.sig_bridges.connect(self._set_bridge_status)
        self.sig_update.connect(self._show_update_dialog)
        self.sig_info.connect(self._show_info)

    # ── Terminal helpers ─────────────────────────────────────────────────────────
    _COLORS = {"info": SUBTEXT, "ok": OK, "warn": WARN, "error": ERR,
               "accent": ACCENT, "dim": MUTED}

    def _append_log(self, message, level):
        color = self._COLORS.get(level, SUBTEXT)
        sym = {"info": "•", "ok": "✔", "warn": "⚠", "error": "✖",
               "accent": "›", "dim": "·"}.get(level, "•")
        safe = (message.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))
        html = (f'<span style="color:{MUTED};">[{core.ts()}]</span> '
                f'<span style="color:{color};">{sym} {safe}</span>')
        self._log_term.append(html)
        self._log_term.moveCursor(QTextCursor.End)

    def log(self, message, level="info"):
        self.sig_log.emit(message, level)

    # ── Status / progress ────────────────────────────────────────────────────────
    def _set_status(self, status):
        self._status = status
        if status == "connected":
            self._status_chip.setText("CONNECTED")
            self._apply_chip(OK)
            self._connect_btn.setEnabled(False)
            self._disconnect_btn.setEnabled(True)
            self._newid_btn.setEnabled(True)
            self._test_btn.setEnabled(True)
            self._refresh_btn.setEnabled(False)
            self._connect_secs = 0
            self._uptime_timer.start(1000)
            self._set_progress(100, "bootstrapped · 100%")
        elif status == "connecting":
            self._status_chip.setText("CONNECTING…")
            self._apply_chip(WARN)
            self._connect_btn.setEnabled(False)
            self._disconnect_btn.setEnabled(True)   # allow cancelling the attempt
            self._newid_btn.setEnabled(False)
            self._test_btn.setEnabled(False)
            self._refresh_btn.setEnabled(False)
        else:
            self._status_chip.setText("DISCONNECTED")
            self._apply_chip(ERR)
            self._connect_btn.setEnabled(True)
            self._disconnect_btn.setEnabled(False)
            self._newid_btn.setEnabled(False)
            self._test_btn.setEnabled(False)
            self._refresh_btn.setEnabled(True)
            self._uptime_timer.stop()
            self._uptime_lbl.setText("Uptime: —")
            self._ip_lbl.setText("—")
            self._set_progress(0, "idle")

    def _set_progress(self, pct, label):
        self._progress.setValue(max(0, min(pct, 100)))
        self._progress_lbl.setText(label)

    def _tick_uptime(self):
        self._connect_secs += 1
        h, rem = divmod(self._connect_secs, 3600)
        m, s = divmod(rem, 60)
        self._uptime_lbl.setText(f"Uptime: {h:02d}:{m:02d}:{s:02d}")

    def _set_ip(self, ip, level):
        self._ip_lbl.setText(ip)
        self._ip_lbl.setStyleSheet(
            f"color: {self._COLORS.get(level, OK)}; font-size: 24px;"
            f" font-weight: 800; font-family: {MONO};")

    def _set_bridge_status(self, text, level):
        self._bridge_status.setText(text)
        self._bridge_status.setStyleSheet(
            f"color: {self._COLORS.get(level, SUBTEXT)}; font-size: 13px; font-weight: 700;")

    def _show_info(self, title, msg, level):
        fn = {"ok": InfoBar.success, "warn": InfoBar.warning,
              "error": InfoBar.error}.get(level, InfoBar.info)
        fn(title=title, content=msg, orient=Qt.Horizontal, isClosable=True,
           position=InfoBarPosition.TOP_RIGHT, duration=4000, parent=self)

    # ── Circuits rendering ──────────────────────────────────────────────────────
    @staticmethod
    def _flag(cc):
        """Regional-indicator flag emoji from a 2-letter country code."""
        cc = (cc or "").upper()
        if len(cc) == 2 and cc.isalpha():
            return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)
        return "🏴"

    def _country_label(self, cc):
        """e.g. 'FR' → '🇫🇷 France'; unknown → '🏴 Unknown'."""
        cc = (cc or "??").upper()
        name = COUNTRY_NAMES.get(cc, "Unknown" if cc in ("??", "") else cc)
        return f"{self._flag(cc)} {name}"

    def _render_circuits(self, circuits):
        if not circuits:
            self._circuits.setHtml(
                f'<span style="color:{MUTED}; font-family:{MONO};">'
                "Building circuits…</span>")
            return
        roles = [(ENTRY, "●", "Entry Guard "),
                 (MIDDLE, "●", "Middle Relay"),
                 (EXIT, "●", "Exit Node   ")]
        out = [f'<div style="font-family:{MONO}; font-size:15px; line-height:170%;">']
        for circ in circuits:
            # Exit-node country headlines the circuit (that's your apparent location).
            exit_cc = circ["path"][-1][3] if circ["path"] and len(circ["path"][-1]) > 3 else "??"
            out.append(
                f'<span style="color:{ACCENT};">╭─ Circuit #{circ["id"]}</span>'
                f'<span style="color:{MUTED};">   exit → </span>'
                f'<span style="color:{TEXT}; font-weight:bold;">{self._country_label(exit_cc)}</span><br>')
            n = len(circ["path"])
            for idx, hop in enumerate(circ["path"]):
                fp, nick, ip = hop[0], hop[1], hop[2]
                cc = hop[3] if len(hop) > 3 else "??"
                conn = "│   " if idx < n - 1 else "╰─  "
                col, dot, label = roles[idx] if idx < 3 else (MUTED, "○", f"Hop {idx+1}    ")
                out.append(
                    f'<span style="color:{MUTED};">{conn}</span>'
                    f'<span style="color:{col};">{dot} {label}</span> '
                    f'<span style="color:{TEXT};">{ip:<16}</span> '
                    f'<span style="color:{ACCENT}; font-weight:bold;">'
                    f'({self._country_label(cc)})</span><br>')
            out.append("<br>")
        out.append("</div>")
        self._circuits.setHtml("".join(out))
        self._circ_ts.setText(f"updated {core.ts()}")

    # ── Environment / bridges / updates ──────────────────────────────────────────
    def _log_environment(self):
        if core.IS_WINDOWS:
            self.log("Ready — routing via per-user system proxy (no admin needed).", "ok")
        elif core.check_root():
            self.log("Running as root — system-wide routing available.", "ok")
        else:
            self.log("Not root — routing unavailable. Launch via 'torshield'.", "warn")
        self.log(f"Tor binary : {core.TOR_EXE_PATH}", "dim")
        self.log(f"Snowflake  : {core.SNOWFLAKE_CLIENT or 'not installed'}",
                 "dim" if core.SNOWFLAKE_CLIENT else "warn")
        self.log(f"obfs4proxy : {core.OBFS4PROXY or 'not installed'}",
                 "dim" if core.OBFS4PROXY else "warn")
        self.log(f"Version    : {core.__version__}", "dim")

    def _startup_tor_and_bridges(self):
        # Quietly repair any leftover TUN/DNS state from a previous crashed or
        # force-closed run, so the machine self-heals on launch (no manual reset).
        if core.IS_WINDOWS:
            try:
                core.cleanup_stale_routing()
            except Exception:
                pass
        # On Windows, fetch Tor itself if it isn't already available, so the app is
        # self-contained and does not require Tor Browser to be installed.
        try:
            if core.IS_WINDOWS and not os.path.isfile(core.TOR_EXE_PATH):
                self.log("Tor not found — downloading the official Tor Expert "
                         "Bundle now (no Tor Browser needed, one-time ~22 MB)…",
                         "accent")
                core.ensure_tor_installed(log=lambda m: self.log(m, "dim"))
                self.log(f"Tor binary : {core.TOR_EXE_PATH}",
                         "ok" if os.path.isfile(core.TOR_EXE_PATH) else "warn")
                self.log(f"Transports : {core.OBFS4PROXY or 'not installed'}",
                         "dim" if core.OBFS4PROXY else "warn")
        except Exception as exc:
            self.log(f"Tor auto-install problem: {exc}", "warn")
        self._prefetch_bridges()

    def _prefetch_bridges(self):
        try:
            country = core.COUNTRY_CODES.get(self._country.currentText(), "").strip("{}")
            if core.bridges_are_stale():
                self.sig_bridges.emit("↻  fetching bridges from Tor…", "info")
                self.log("Fetching obfs4 + snowflake bridges from Tor…", "info")
                counts = core.refresh_all_bridges(country=country)
            else:
                counts = {"obfs4": len(core.load_obfs4_bridges()),
                          "snowflake": len(core._load_bridges("snowflake"))}
            self._report_bridges(counts)
        except Exception:
            pass

    def _report_bridges(self, counts):
        o, s = counts.get("obfs4", 0), counts.get("snowflake", 0)
        if o or s:
            self.sig_bridges.emit(f"✔  {o} obfs4 · {s} snowflake ready", "ok")
            self.log(f"Bridges ready: {o} obfs4, {s} snowflake (Tor BridgeDB).", "ok")
        else:
            self.sig_bridges.emit("⚠  fetch failed — built-in fallback", "warn")
            self.log("Bridge fetch failed — using built-in Snowflake fallback.", "warn")

    def _on_refresh_bridges(self):
        self._refresh_btn.setEnabled(False)
        self.sig_bridges.emit("↻  fetching bridges from Tor…", "info")
        def _w():
            try:
                country = core.COUNTRY_CODES.get(self._country.currentText(), "").strip("{}")
                self._report_bridges(core.refresh_all_bridges(country=country, force=True))
            finally:
                if self._status != "connected":
                    self._refresh_btn.setEnabled(True)
        threading.Thread(target=_w, daemon=True).start()

    def _check_updates(self):
        try:
            info = core.check_for_update()
            if info.get("available"):
                self.sig_update.emit(info)
            else:
                self.log(f"You're on the latest version ({core.__version__}).", "dim")
        except Exception:
            pass

    def _show_update_dialog(self, info):
        box = MessageBox(
            "Update available",
            f"A new version of TorShield is available.\n\n"
            f"Installed: {info['current']}      Latest: {info['remote']}\n\n"
            "Update now to get the latest features and fixes.",
            self)
        box.yesButton.setText("Update now")
        box.cancelButton.setText("Maybe later")
        if box.exec():
            self._do_update()
        else:
            self.log("Update postponed — you can update later by reopening.", "dim")

    def _do_update(self):
        self.log("Starting update…", "accent")
        def _w():
            ok = core.perform_update(log=lambda m, l="info": self.log(m, l))
            if ok:
                self.sig_info.emit("Updated", "Restarting TorShield…", "ok")
                if self._routing_active:
                    core.disable_system_routing()
                self._tor.stop_tor()
                QTimer.singleShot(1200, core.restart_app)
            else:
                self.sig_info.emit("Update failed",
                                   "Could not update automatically.", "error")
        threading.Thread(target=_w, daemon=True).start()

    # ── Connection flow (auto: Direct → Snowflake → obfs4) ──────────────────────
    def _mode_sequence(self):
        seq = ["Direct"]
        if core.IS_WINDOWS:
            # obfs4 is faster and more reliable than snowflake, so try it first on
            # Windows. Linux keeps the original Snowflake → obfs4 order below.
            if core.OBFS4PROXY:
                seq.append("obfs4")
            if core.SNOWFLAKE_CLIENT:
                seq.append("Snowflake")
        else:
            if core.SNOWFLAKE_CLIENT:
                seq.append("Snowflake")
            if core.OBFS4PROXY:
                seq.append("obfs4")
        return seq

    def _attempt_mode(self, mode, timeout):
        if self._cancel.is_set():
            return False
        self.log(f"Trying connection mode: {mode}…", "accent")
        self.sig_progress.emit(0, f"{mode}: starting Tor…")
        if mode == "obfs4" and not core.load_obfs4_bridges():
            self.log("Fetching obfs4 bridges from Tor…", "info")
            country = core.COUNTRY_CODES.get(self._country.currentText(), "").strip("{}")
            core.refresh_all_bridges(country=country, force=True)
            if not core.load_obfs4_bridges():
                self.log("obfs4 unavailable (could not fetch bridges).", "warn")
                return False
        # Windows torrc lives in the user's AppData (always writable); Linux's is
        # /etc/tor/torrc which needs root. Apply the bridge mode whenever we can.
        if core.IS_WINDOWS or core.check_root():
            try:
                core.apply_bridge_mode(mode)
            except Exception as exc:
                self.log(f"Could not write torrc for {mode}: {exc}", "error")
                return False
        self._tor.stop_tor()
        try:
            self._tor.start_tor()
        except Exception as exc:
            self.log(f"{mode}: Tor failed to start — {exc}", "error")
            return False
        try:
            self._tor.connect_controller(
                max_retries=12, delay=1.5,
                should_continue=lambda: not self._cancel.is_set())
        except Exception as exc:
            if not self._cancel.is_set():
                self.log(f"{mode}: control port not ready — {exc}", "warn")
            return False
        if self._cancel.is_set():
            return False
        ok = self._tor.wait_for_bootstrap(
            timeout=timeout,
            on_progress=lambda p: self.sig_progress.emit(p, f"{mode}: bootstrapping… {p}%"),
            should_continue=lambda: not self._cancel.is_set(),
            # Windows: bail out of a stuck mode after 75s of no progress so we move
            # on to a working one quickly (the slow descriptor gaps on a throttled
            # link can be ~60s, so 75s avoids false stalls). Linux passes nothing
            # and keeps its original fixed-timeout behaviour.
            stall_after=(75.0 if core.IS_WINDOWS else None))
        if self._cancel.is_set():
            return False
        self.log(f"{mode}: {'bootstrapped' if ok else 'stalled'}.",
                 "ok" if ok else "warn")
        return ok

    def _on_connect(self):
        self._cancel.clear()
        self.sig_status.emit("connecting")
        seq = self._mode_sequence()
        self.log(f"Connecting (plan: {' → '.join(seq)})", "info")
        if core.IS_WINDOWS:
            # Windows starts from a cold tor-data on first connect, so the very
            # first bootstrap must download the whole consensus + microdescriptors
            # and can take 1–2 minutes. Linux usually reuses a warm system Tor
            # cache and stays on the original, tighter timeouts.
            timeouts = {"Direct": 90.0, "Snowflake": 120.0, "obfs4": 120.0}
        else:
            timeouts = {"Direct": 25.0, "Snowflake": 75.0, "obfs4": 60.0}

        def _w():
            connected = None
            for mode in seq:
                if self._cancel.is_set():
                    break
                if self._attempt_mode(mode, timeouts.get(mode, 60.0)):
                    connected = mode
                    break
            # Cancelled by the user (Disconnect during connecting) — bail quietly.
            if self._cancel.is_set():
                self._tor.stop_tor()
                self.sig_status.emit("disconnected")
                self.log("Connection cancelled.", "warn")
                return
            if not connected:
                self._tor.stop_tor()
                self.sig_status.emit("disconnected")
                self.log("Could not bootstrap with any mode.", "error")
                self.sig_info.emit("Connection failed",
                                   "Tor could not connect in any mode.", "error")
                return
            try:
                # Pin the exit country if requested — but never let a failure here
                # stop us from showing circuits / marking the session connected.
                cc = core.COUNTRY_CODES.get(self._country.currentText(), "")
                if cc:
                    try:
                        self._tor.set_exit_node(cc)
                        self.log(f"Pinning exit to {self._country.currentText()} — "
                                 "rebuilding circuits…", "accent")
                        if self._tor.exit_country_ok(cc, timeout=25):
                            self.log(f"Exit node set to: {self._country.currentText()}",
                                     "ok")
                        else:
                            # Country has no usable Tor exit right now — fall back to
                            # any exit so the user actually gets internet.
                            self.log(f"{self._country.currentText()} has no available "
                                     "Tor exit right now — using the best available "
                                     "exit so you stay online.", "warn")
                            self._tor.set_exit_node("")
                    except Exception as exc:
                        self.log(f"Could not pin exit to "
                                 f"{self._country.currentText()}: {exc}", "warn")
                # Start circuit monitoring and mark connected BEFORE routing, so the
                # circuits panel populates even if routing has trouble.
                self._tor.start_circuit_monitoring(
                    callback=lambda c: self.sig_circuits.emit(c), interval=5.0)
                self.sig_status.emit("connected")
                self.log(f"Connected via {connected}!", "ok")
                self.sig_info.emit("Connected", f"Tor is up via {connected}.", "ok")
                # AUTOMATIC routing (no switch) — shown step by step. On Windows
                # this is a per-user system-proxy setting that needs no admin; on
                # Linux it still requires root for iptables.
                if core.IS_WINDOWS or core.check_root():
                    try:
                        self._auto_route()
                    except Exception as exc:
                        self.log(f"Routing error (Tor is still connected): {exc}",
                                 "warn")
                else:
                    self.log("Not root — cannot route system traffic.", "warn")
            except Exception as exc:
                self.sig_status.emit("disconnected")
                self.log(f"Post-connect error: {exc}", "error")
        threading.Thread(target=_w, daemon=True).start()

    def _auto_route(self):
        self.log("Routing traffic through Tor…", "accent")
        if core.IS_WINDOWS:
            self.log("  • bringing up TUN VPN adapter (all apps → Tor)", "dim")
            self.log("  • routing Tor's own relays around the tunnel", "dim")
            self.log("  • DNS resolved through Tor", "dim")
        else:
            self.log("  • flushing conntrack (prevents pre-Tor leaks)", "dim")
            self.log("  • redirecting TCP → Tor TransPort 9040", "dim")
            self.log("  • redirecting DNS → Tor DNSPort 5353", "dim")
            self.log("  • blocking QUIC (UDP 443/80)", "dim")
        ok, msg = core.enable_system_routing(
            tor_pid=core.IS_WINDOWS and self._tor.tor_pid() or None,
            log=lambda m: self.log(m, "dim"))
        self._routing_active = ok
        self.log(msg, "ok" if ok else "error")
        if ok:
            mode = core.routing_mode()
            if mode == "tun":
                self.log("Every app on this machine now goes through Tor.", "ok")
                self.sig_info.emit("VPN active", "All apps now route through Tor.", "ok")
            elif mode == "proxy":
                # Fallback path (not elevated / TUN unavailable): the proxy only
                # covers proxy-aware apps, so restart the browser through Tor too.
                self.log("Full-VPN unavailable — using proxy mode. Restarting your "
                         "browser through Tor…", "warn")
                bok, bmsg = core.open_secure_browser()
                self.log(bmsg, "ok" if bok else "warn")
                self.sig_info.emit("Routing active (proxy mode)",
                                   "Browser routes through Tor. Run as admin for "
                                   "all-apps VPN.", "ok")
            else:
                self.log("Every app on this machine now uses Tor.", "ok")
                self.sig_info.emit("Routing active",
                                   "All traffic now goes through Tor.", "ok")

    def _on_disconnect(self):
        cancelling = self._status == "connecting"
        # Signal any in-progress connection worker to abort immediately.
        self._cancel.set()
        # Avoid double handling: if we're cancelling a connect, that worker owns
        # the teardown — just stop Tor so its current step unblocks fast.
        if cancelling:
            self.log("Cancelling connection…", "warn")
            self._disconnect_btn.setEnabled(False)
            threading.Thread(target=self._tor.stop_tor, daemon=True).start()
            return

        self.log("Disconnecting…")
        self._tor.stop_circuit_monitoring()
        was_routing = self._routing_active
        self._routing_active = False
        self._disconnect_btn.setEnabled(False)   # prevent double-clicks during teardown
        # Everything below (restore routing, remove the TUN adapter, stop Tor) can
        # take a few seconds, so run it OFF the GUI thread — otherwise the window
        # goes "Not responding" until it finishes.
        def _w():
            if was_routing:
                self.log("Restoring direct routing…")
                ok, msg = core.disable_system_routing()
                self.log(msg, "ok" if ok else "error")
            self._tor.stop_tor()
            # Windows: full reset AFTER disconnect — remove the TUN adapter, clear any
            # pinned DNS, re-enable IPv6 and flush the DNS cache — so the internet is
            # always clean once disconnected (no manual reset, no leftover state).
            if core.IS_WINDOWS:
                self.log("Cleaning up network + flushing DNS…", "dim")
                core.cleanup_stale_routing()
            self.sig_status.emit("disconnected")
            self.sig_circuits.emit([])
            self.log("Tor stopped. Internet restored.", "ok")
        threading.Thread(target=_w, daemon=True).start()

    def _on_country_change(self, selection):
        cc = core.COUNTRY_CODES.get(selection, "")
        if self._status != "connected":
            self.log(f"Exit node queued: {selection}")
            return
        def _w():
            try:
                self._tor.set_exit_node(cc)
                if not cc:
                    self.log("Exit node restriction removed (Random).", "ok")
                elif self._tor.exit_country_ok(cc, timeout=25):
                    self.log(f"Exit node changed to: {selection}", "ok")
                else:
                    self.log(f"{selection} has no available Tor exit right now — "
                             "using the best available exit.", "warn")
                    self._tor.set_exit_node("")
                core.flush_dns()   # drop lookups cached via the old exit country
            except Exception as exc:
                self.log(f"Failed to change exit node: {exc}", "error")
        threading.Thread(target=_w, daemon=True).start()

    def _on_new_identity(self):
        self.log("Requesting new identity (NEWNYM)…")
        def _w():
            try:
                self._tor.new_identity()
                self.log("New identity requested. Circuit rebuilding shortly.", "ok")
            except Exception as exc:
                self.log(f"New identity failed: {exc}", "error")
        threading.Thread(target=_w, daemon=True).start()

    def _on_test(self):
        self.log("Testing connection through Tor SOCKS5 proxy…")
        self._set_ip("…", "warn")
        self._test_btn.setEnabled(False)
        def _w():
            try:
                ip = core.get_tor_public_ip()
                self.sig_ip.emit(ip, "ok")
                self.log(f"Public IP via Tor: {ip}", "ok")
            except Exception as exc:
                self.sig_ip.emit("Error", "error")
                self.log(f"Connection test failed: {exc}", "error")
            finally:
                if self._status == "connected":
                    self._test_btn.setEnabled(True)
        threading.Thread(target=_w, daemon=True).start()

    def _emergency_restore(self):
        """Last-resort cleanup on interpreter exit — restore routing/DNS and stop
        Tor so the user is never left offline. Safe to call more than once."""
        try:
            if getattr(self, "_routing_active", False):
                core.disable_system_routing()
                self._routing_active = False
        except Exception:
            pass
        try:
            self._tor.stop_tor()
        except Exception:
            pass

    def closeEvent(self, event):
        if self._status in ("connected", "connecting"):
            box = MessageBox("Quit TorShield",
                             "Tor is running. Stop Tor and restore normal routing?",
                             self)
            box.yesButton.setText("Quit")
            box.cancelButton.setText("Cancel")
            if not box.exec():
                event.ignore()
                return
        if self._routing_active:
            core.disable_system_routing()
        self._tor.stop_tor()
        event.accept()


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    win = TorShieldWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
