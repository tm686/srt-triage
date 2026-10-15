"""
Curses TUI — cyberpunk-styled host triage dashboard with box-drawing
panels, score bars, and side-by-side layout.
"""

import curses
import threading
import time

from lib import db as db_mod
from lib.scanner import run_tier2
from lib.scorer import rescore_all

# ── Box-drawing characters ───────────────────────────────────────────
TL = "┌"; TR = "┐"; BL = "└"; BR = "┘"
H  = "─"; V  = "│"
LT = "├"; RT = "┤"; TT = "┬"; BT = "┴"; X = "┼"

# ── Block characters for score bars ──────────────────────────────────
BAR_FULL = "█"; BAR_LO = "░"

# ── Color pair indices ───────────────────────────────────────────────
C_BORDER = 1;  C_TITLE = 2;   C_HIGH = 3;    C_MED = 4
C_LOW = 5;     C_PROMO = 6;   C_INTER = 7;   C_SKIP = 8
C_SEL = 9;     C_STATUS = 10; C_DHDR = 11;   C_DTXT = 12
C_BARHI = 13;  C_BARMD = 14;  C_BARLO = 15;  C_LOGO = 16
C_DIM = 17;    C_ACCENT = 18; C_BPROMO = 19; C_BINTER = 20
C_BSKIP = 21;  C_SCRIPT = 22; C_VULN = 23;   C_INPUT = 24

LOGO = [
    r"         _        _       _                  ",
    r"  ___ _ _| |_ ___ | |_ _ _|_|___ ___ ___     ",
    r" |_ -|  _|  _|___||  _|  _| | .'| . | -_|    ",
    r" |___|_| |_|      |_| |_| |_|__,|_  |___|    ",
    r"                                |___|         ",
]


def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_BORDER, curses.COLOR_CYAN,   -1)
    curses.init_pair(C_TITLE,  curses.COLOR_GREEN,  -1)
    curses.init_pair(C_HIGH,   curses.COLOR_RED,    -1)
    curses.init_pair(C_MED,    curses.COLOR_YELLOW, -1)
    curses.init_pair(C_LOW,    curses.COLOR_GREEN,  -1)
    curses.init_pair(C_PROMO,  curses.COLOR_CYAN,   -1)
    curses.init_pair(C_INTER,  curses.COLOR_GREEN,  -1)
    curses.init_pair(C_SKIP,   curses.COLOR_WHITE,  -1)
    curses.init_pair(C_SEL,    curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_STATUS, curses.COLOR_BLACK,  curses.COLOR_GREEN)
    curses.init_pair(C_DHDR,   curses.COLOR_CYAN,   -1)
    curses.init_pair(C_DTXT,   curses.COLOR_WHITE,  -1)
    curses.init_pair(C_BARHI,  curses.COLOR_RED,    -1)
    curses.init_pair(C_BARMD,  curses.COLOR_YELLOW, -1)
    curses.init_pair(C_BARLO,  curses.COLOR_GREEN,  -1)
    curses.init_pair(C_LOGO,   curses.COLOR_CYAN,   -1)
    curses.init_pair(C_DIM,    curses.COLOR_WHITE,  -1)
    curses.init_pair(C_ACCENT, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_BPROMO, curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_BINTER, curses.COLOR_BLACK,  curses.COLOR_YELLOW)
    curses.init_pair(C_BSKIP,  curses.COLOR_WHITE,  -1)
    curses.init_pair(C_SCRIPT, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_VULN,   curses.COLOR_RED,    -1)
    curses.init_pair(C_INPUT,  curses.COLOR_GREEN,  -1)


def _bar(score, width=10, cap=200):
    filled = min(int((score / cap) * width), width)
    return BAR_FULL * filled + BAR_LO * (width - filled)


def _bar_color(score):
    if score >= 80:  return curses.color_pair(C_BARHI) | curses.A_BOLD
    if score >= 30:  return curses.color_pair(C_BARMD)
    return curses.color_pair(C_BARLO)


def _badge(triage):
    if triage == "promoted":    return " PROMO ", curses.color_pair(C_BPROMO) | curses.A_BOLD
    if triage == "interesting": return " INTER ", curses.color_pair(C_BINTER) | curses.A_BOLD
    if triage == "skip":        return " SKIP  ", curses.color_pair(C_BSKIP) | curses.A_DIM
    return "  ---  ", curses.color_pair(C_DIM) | curses.A_DIM


class TriageTUI:
    def __init__(self, stdscr, conn, config):
        self.scr = stdscr
        self.conn = conn
        self.config = config
        self.hosts = []
        self.cursor = 0
        self.scroll = 0
        self.dscroll = 0
        self.status_msg = "Ready"
        self.status_t = 0
        self.filter_text = ""
        self.input_mode = None
        self.input_buf = ""
        self.scan_thread = None
        _init_colors()
        curses.curs_set(0)
        self.refresh_hosts()

    def w(self, r, c, s, a=0):
        """Safe write."""
        try:
            self.scr.addstr(r, c, s, a)
        except curses.error:
            pass

    def refresh_hosts(self):
        h = db_mod.get_hosts_ranked(self.conn)
        if self.filter_text:
            f = self.filter_text.lower()
            h = [x for x in h if f in x["ip"].lower()
                 or f in x.get("hostname", "").lower()
                 or f in x.get("triage", "").lower()]
        self.hosts = h
        if self.cursor >= len(self.hosts):
            self.cursor = max(0, len(self.hosts) - 1)

    def _status(self, msg):
        self.status_msg = msg
        self.status_t = time.time()

    # ── Drawing ──────────────────────────────────────────────────────

    def _draw(self):
        my, mx = self.scr.getmaxyx()
        if my < 12 or mx < 60:
            self.scr.clear()
            self.w(0, 0, "Terminal too small (60x12 min)", curses.color_pair(C_VULN))
            self.scr.refresh()
            return

        self.scr.erase()
        bc = curses.color_pair(C_BORDER)

        # ── Layout calculation ───────────────────────────────────────
        lw = max(40, min(int(mx * 0.50), mx - 30))  # left panel width
        rw = mx - lw                                  # right panel width

        # Row 0: top border
        self.w(0, 0, TL + H * (mx - 2) + TR, bc)

        # Rows 1-5: logo
        for i, line in enumerate(LOGO):
            r = 1 + i
            txt = f" {line}"[:mx - 2].ljust(mx - 2)
            self.w(r, 0, V, bc)
            self.w(r, 1, txt, curses.color_pair(C_LOGO) | curses.A_BOLD)
            self.w(r, mx - 1, V, bc)

        # Row 6: stats separator
        sr = 1 + len(LOGO)
        self.w(sr, 0, LT + H * (mx - 2) + RT, bc)

        # Row 7: stats bar
        sr += 1
        self.w(sr, 0, V, bc)
        self.w(sr, mx - 1, V, bc)

        t1 = sum(1 for h in self.hosts if h.get("tier", 1) == 1)
        t2 = sum(1 for h in self.hosts if h.get("tier", 1) == 2)
        promo = sum(1 for h in self.hosts if h.get("triage") == "promoted")
        inter = sum(1 for h in self.hosts if h.get("triage") == "interesting")
        skip = sum(1 for h in self.hosts if h.get("triage") == "skip")
        top_s = self.hosts[0]["score"] if self.hosts else 0

        dc = curses.color_pair(C_DIM)
        c = 2
        for label, val, color in [
            ("HOSTS", len(self.hosts), curses.color_pair(C_ACCENT) | curses.A_BOLD),
            ("T1", t1, curses.color_pair(C_TITLE) | curses.A_BOLD),
            ("T2", t2, curses.color_pair(C_PROMO) | curses.A_BOLD),
            (V + " PROMO", promo, curses.color_pair(C_PROMO) | curses.A_BOLD),
            ("INTER", inter, curses.color_pair(C_INTER) | curses.A_BOLD),
            ("SKIP", skip, dc),
            (V + " TOP", top_s, _bar_color(top_s)),
        ]:
            self.w(sr, c, label + " ", dc)
            c += len(label) + 1
            self.w(sr, c, str(val), color)
            c += len(str(val)) + 2

        # Row 8: panel headers separator
        ph = sr + 1
        # Left: ├──TARGETS──┬  Right: ──DETAIL──┤
        self.w(ph, 0, LT, bc)
        lt = " TARGETS "
        bl = (lw - 2 - len(lt)) // 2
        br_ = lw - 2 - len(lt) - bl
        self.w(ph, 1, H * bl, bc)
        self.w(ph, 1 + bl, lt, curses.color_pair(C_TITLE) | curses.A_BOLD)
        self.w(ph, 1 + bl + len(lt), H * br_, bc)
        self.w(ph, lw - 1, TT, bc)

        dt = " DETAIL "
        dl = (rw - 2 - len(dt)) // 2
        dr = rw - 2 - len(dt) - dl
        self.w(ph, lw, H * dl, bc)
        self.w(ph, lw + dl, dt, curses.color_pair(C_DHDR) | curses.A_BOLD)
        self.w(ph, lw + dl + len(dt), H * dr, bc)
        self.w(ph, mx - 1, RT, bc)

        # Row 9: column headers
        ch = ph + 1
        self.w(ch, 0, V, bc)
        hdr = f" {'#':>2} {'IP':<16} {'Score':>5} {'':10} {'Triage':7}"
        self.w(ch, 1, hdr[:lw - 2].ljust(lw - 2),
               curses.color_pair(C_DIM) | curses.A_UNDERLINE)
        self.w(ch, lw - 1, V, bc)
        self.w(ch, lw, " " * (rw - 1))
        self.w(ch, mx - 1, V, bc)

        # Content area: rows ch+1 to my-3
        content_top = ch + 1
        content_bot = my - 2  # row my-2 = bottom border, my-1 = status
        avail = content_bot - content_top
        if avail < 1:
            avail = 1

        # ── Left panel: host list ────────────────────────────────────
        if self.cursor < self.scroll:
            self.scroll = self.cursor
        if self.cursor >= self.scroll + avail:
            self.scroll = self.cursor - avail + 1

        for i in range(avail):
            r = content_top + i
            idx = self.scroll + i
            self.w(r, 0, V, bc)

            if idx < len(self.hosts):
                h = self.hosts[idx]
                rank = idx + 1
                score = h.get("score", 0)
                tri = h.get("triage", "unreviewed")
                sel = (idx == self.cursor)

                if sel:
                    line = f" {rank:>2} {h['ip']:<16} {score:>5}  "
                    b = _bar(score, 10)
                    bt_, _ = _badge(tri)
                    full = (line + b + " " + bt_)[:lw - 2].ljust(lw - 2)
                    self.w(r, 1, full, curses.color_pair(C_SEL))
                else:
                    col = 1
                    pref = f" {rank:>2} "
                    self.w(r, col, pref, curses.color_pair(C_DIM))
                    col += len(pref)

                    ip_c = curses.color_pair(C_DIM) | curses.A_DIM if tri == "skip" else curses.color_pair(C_DTXT)
                    ips = f"{h['ip']:<16} "
                    self.w(r, col, ips, ip_c)
                    col += len(ips)

                    ss = f"{score:>5}  "
                    self.w(r, col, ss, _bar_color(score))
                    col += len(ss)

                    b = _bar(score, 10)
                    self.w(r, col, b, _bar_color(score))
                    col += len(b) + 1

                    bt_, ba = _badge(tri)
                    if col + len(bt_) < lw - 1:
                        self.w(r, col, bt_, ba)
            else:
                self.w(r, 1, " " * (lw - 2))

            self.w(r, lw - 1, V, bc)

        # ── Right panel: detail ──────────────────────────────────────
        lines = self._build_detail_lines(rw - 2)
        if self.dscroll > max(0, len(lines) - avail):
            self.dscroll = max(0, len(lines) - avail)

        for i in range(avail):
            r = content_top + i
            li = self.dscroll + i
            self.w(r, lw, " " * (rw - 1))
            if li < len(lines):
                tp, txt = lines[li]
                txt = txt[:rw - 2]
                col_map = {
                    "hdr":       curses.color_pair(C_DHDR) | curses.A_BOLD,
                    "section":   curses.color_pair(C_DHDR) | curses.A_BOLD,
                    "sep":       bc | curses.A_DIM,
                    "port":      curses.color_pair(C_HIGH),
                    "script":    curses.color_pair(C_SCRIPT),
                    "vuln":      curses.color_pair(C_VULN) | curses.A_BOLD,
                    "bar":       _bar_color(self.hosts[self.cursor].get("score", 0) if self.hosts else 0),
                    "breakdown": curses.color_pair(C_ACCENT),
                    "dim":       curses.color_pair(C_DIM) | curses.A_DIM,
                }
                attr = col_map.get(tp, curses.color_pair(C_DTXT))
                if tp == "sep":
                    txt = H * (rw - 2)
                self.w(r, lw + 1, txt, attr)
            self.w(r, mx - 1, V, bc)

        # ── Bottom border ────────────────────────────────────────────
        br = my - 2
        self.w(br, 0, BL + H * (lw - 2) + BT + H * (rw - 2) + BR, bc)

        # ── Status bar ───────────────────────────────────────────────
        self._draw_status(my, mx)

        self.scr.noutrefresh()
        curses.doupdate()

    def _build_detail_lines(self, width):
        """Build list of (type, text) lines for the detail panel."""
        if not self.hosts:
            return [("dim", " No hosts loaded")]

        host = self.hosts[self.cursor]
        detail = db_mod.get_host_detail(self.conn, host["id"])
        if not detail:
            return [("dim", " No data")]

        lines = []
        hn = detail.get("hostname", "")
        tier = f"T{detail.get('tier', 1)}"
        tri = detail.get("triage", "unreviewed")
        lines.append(("hdr", f" {detail['ip']}  {hn}  [{tier}]"))
        lines.append(("sep", ""))

        # Ports
        lines.append(("section", " OPEN PORTS"))
        for p in detail.get("ports", []):
            svc = p.get("service", "?")
            prod = p.get("product", "")
            ver = p.get("version", "")
            pv = f"  {prod} {ver}".rstrip() if prod else ""
            lines.append(("port", f"  \u25cf {p['port']:<6} {svc:<14}{pv}"))

        # Scripts
        has_scripts = any(p.get("scripts") for p in detail.get("ports", []))
        if detail.get("host_scripts"):
            has_scripts = True
        if has_scripts:
            lines.append(("sep", ""))
            lines.append(("section", " NSE SCRIPTS"))
            for p in detail.get("ports", []):
                for s in p.get("scripts", []):
                    sid = s["script_id"]
                    out = s["output"][:width - 10].replace("\n", " ").strip() if s["output"] else ""
                    is_v = "vuln" in sid.lower() or "VULNERABLE" in (s["output"] or "")
                    tag = "vuln" if is_v else "script"
                    lines.append((tag, f"  [{p['port']}] {sid}"))
                    if out:
                        lines.append((tag, f"       {out}"))
            for s in detail.get("host_scripts", []):
                sid = s["script_id"]
                out = s["output"][:width - 10].replace("\n", " ").strip() if s["output"] else ""
                lines.append(("script", f"  [host] {sid}"))
                if out:
                    lines.append(("script", f"       {out}"))

        # Score
        lines.append(("sep", ""))
        score = detail.get("score", 0)
        lines.append(("section", " SCORE"))
        lines.append(("bar", f"  {_bar(score, 20)} {score}"))
        if detail.get("breakdown"):
            for b in detail["breakdown"][:8]:
                lines.append(("breakdown", f"    +{b['score']:<4} {b['signal']}"))

        return lines

    def _draw_status(self, my, mx):
        r = my - 1
        if self.input_mode == "filter":
            line = f"  / {self.input_buf}\u2588"
            self.w(r, 0, line.ljust(mx)[:mx], curses.color_pair(C_INPUT) | curses.A_BOLD)
            return

        sc = curses.color_pair(C_STATUS) | curses.A_BOLD
        msg = ""
        if self.status_msg and (time.time() - self.status_t < 5):
            msg = f"  {self.status_msg}  "
        elif self.filter_text:
            msg = f"  filter: {self.filter_text}  "
        else:
            msg = "  "

        keys = "\u2191\u2193:nav  i:interest  s:skip  p:promote  t:tier2  r:rescore  /:filter  q:quit"
        line = msg + keys
        self.w(r, 0, line.ljust(mx)[:mx], sc)

    # ── Triage actions ───────────────────────────────────────────────

    def _triage(self, key):
        if not self.hosts:
            return
        h = self.hosts[self.cursor]
        hid = h["id"]
        if key == "i":
            db_mod.set_triage(self.conn, hid, "interesting")
            self._status(f"\u2605 {h['ip']} \u2192 interesting")
        elif key == "s":
            db_mod.set_triage(self.conn, hid, "skip")
            self._status(f"\u2013 {h['ip']} \u2192 skip")
        elif key == "p":
            db_mod.promote_host(self.conn, hid)
            self._status(f"\u25b2 {h['ip']} \u2192 promoted (Tier 2)")
        self.refresh_hosts()

    def _tier2(self):
        promoted = db_mod.get_promoted_hosts(self.conn)
        if not promoted:
            self._status("No promoted hosts for Tier 2")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            self._status("Scan already running...")
            return
        self._status(f"Tier 2 scanning {len(promoted)} host(s)...")

        def go():
            for h in promoted:
                run_tier2(h["ip"], self.conn, self.config, status_cb=self._status)
            self.refresh_hosts()
            self._status("Tier 2 complete")

        self.scan_thread = threading.Thread(target=go, daemon=True)
        self.scan_thread.start()

    def _rescore(self):
        self._status("Re-scoring...")
        rescore_all(self.conn, self.config.get("config_dir", "config"))
        self.refresh_hosts()
        self._status("Re-scoring complete")

    # ── Main loop ────────────────────────────────────────────────────

    def run(self):
        self.scr.timeout(500)
        self.status_t = time.time()

        while True:
            try:
                self._draw()
            except curses.error:
                pass

            key = self.scr.getch()
            if key == -1:
                continue

            # Filter input
            if self.input_mode == "filter":
                if key in (27, curses.KEY_BREAK):
                    self.input_mode = None
                    self.filter_text = ""
                    self.input_buf = ""
                    self.refresh_hosts()
                elif key in (10, 13, curses.KEY_ENTER):
                    self.filter_text = self.input_buf
                    self.input_mode = None
                    self.input_buf = ""
                    self.cursor = 0
                    self.scroll = 0
                    self.refresh_hosts()
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    self.input_buf = self.input_buf[:-1]
                elif 32 <= key <= 126:
                    self.input_buf += chr(key)
                continue

            # Normal keys
            if key == ord("q"):
                break
            elif key in (ord("j"), curses.KEY_DOWN):
                if self.cursor < len(self.hosts) - 1:
                    self.cursor += 1
                    self.dscroll = 0
            elif key in (ord("k"), curses.KEY_UP):
                if self.cursor > 0:
                    self.cursor -= 1
                    self.dscroll = 0
            elif key == ord("i"):
                self._triage("i")
            elif key == ord("s"):
                self._triage("s")
            elif key == ord("p"):
                self._triage("p")
            elif key == ord("t"):
                self._tier2()
            elif key == ord("r"):
                self._rescore()
            elif key == ord("/"):
                self.input_mode = "filter"
                self.input_buf = self.filter_text
            elif key == ord("g"):
                self.cursor = 0; self.scroll = 0; self.dscroll = 0
            elif key == ord("G"):
                self.cursor = max(0, len(self.hosts) - 1); self.dscroll = 0
            elif key == curses.KEY_PPAGE:
                self.cursor = max(0, self.cursor - 10); self.dscroll = 0
            elif key == curses.KEY_NPAGE:
                self.cursor = min(max(0, len(self.hosts) - 1), self.cursor + 10); self.dscroll = 0
            elif key in (ord("l"), curses.KEY_RIGHT):
                self.dscroll += 1
            elif key in (ord("h"), curses.KEY_LEFT):
                if self.dscroll > 0:
                    self.dscroll -= 1
