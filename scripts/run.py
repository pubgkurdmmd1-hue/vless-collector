#!/usr/bin/env python3
"""VLESS collector + real tester.

Pipeline:
  1. Read sources.txt (tg:channels and http(s) sub URLs)
  2. Extract vless:// links, static-validate, dedupe
  3. TCP check + REAL end-to-end test through Xray-core (3 targets, need 2/3)
  4. Speed test for passed configs (download through tunnel)
  5. Geo flags (tunnel trace -> ip-api -> channel emoji), OONI Iran check for domains
  6. Score, pick top 20, rename, push to Cloudflare KV + D1
Only stdlib is used (no pip packages needed).
"""

import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
SCHEMA_FILE = os.path.join(ROOT, "worker", "schema.sql")
STATS_FILE = os.path.join(ROOT, "stats.json")
XRAY_BIN = os.environ.get("XRAY_BIN", "./xray")

CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
KV_NAMESPACE_ID = os.environ.get("KV_NAMESPACE_ID", "")
D1_DATABASE_ID = os.environ.get("D1_DATABASE_ID", "")

CANDIDATE_CAP = 120
THREADS_TEST = 25
THREADS_SPEED = 12
SPEED_CAP = 40
PUBLISH_COUNT = 20
FAST_COUNT = 10

TARGETS = [
    "https://www.gstatic.com/generate_204",
    "https://1.1.1.1/cdn-cgi/trace",
    "https://cloudflare.com/cdn-cgi/trace",
]
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=3000000"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
VLESS_RE = re.compile(r"vless://[^\s\"'<>`]+")


def log(*a):
    print("[run]", *a, flush=True)


# ---------------- http helpers ----------------

def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_post_json(url, payload, timeout=25):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CF_API_TOKEN}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def cf_put_kv(key, value_bytes):
    url = (
        f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
        f"/storage/kv/namespaces/{KV_NAMESPACE_ID}"
        f"/values/{urllib.parse.quote(key, safe='')}"
    )
    req = urllib.request.Request(
        url, data=value_bytes, method="PUT",
        headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def kv_get_prev():
    try:
        if not (CF_API_TOKEN and CF_ACCOUNT_ID and KV_NAMESPACE_ID):
            return {}
        key = urllib.parse.quote("results:v1", safe="")
        url = (
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
            f"/storage/kv/namespaces/{KV_NAMESPACE_ID}/values/{key}"
        )
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {CF_API_TOKEN}"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def cf_d1_query(sql, params=None):
    url = (
        f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
        f"/d1/database/{D1_DATABASE_ID}/query"
    )
    return http_post_json(url, {"sql": sql, "params": params or []})


# ---------------- sources ----------------

def load_sources():
    chans, urls = [], []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("tg:"):
                chans.append(line[3:].strip().lstrip("@"))
            elif line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
    return chans, urls


def fetch_channel(channel):
    out = []
    try:
        raw = http_get(f"https://t.me/s/{channel}", timeout=20).decode(
            "utf-8", "ignore"
        )
        out = VLESS_RE.findall(raw)
    except Exception as e:
        log(f"channel {channel}: fetch failed ({e})")
    return [(c, "tg:" + channel) for c in out]


def fetch_url_source(url):
    out = []
    try:
        text = http_get(url, timeout=25).decode("utf-8", "ignore")
        links = VLESS_RE.findall(text)
        if not links:
            try:
                dec = base64.b64decode(text.strip() + "===").decode(
                    "utf-8", "ignore"
                )
                links = VLESS_RE.findall(dec)
            except Exception:
                pass
        out = [(c, url) for c in links]
    except Exception as e:
        log(f"url source failed ({e}): {url[:70]}")
    return out


# ---------------- parse + validate ----------------

def parse_vless(link):
    try:
        link = link.strip()
        if not link.startswith("vless://"):
            return None
        body = link[len("vless://"):]
        remark = ""
        if "#" in body:
            body, remark = body.split("#", 1)
            remark = urllib.parse.unquote(remark)
        query = ""
        if "?" in body:
            body, query = body.split("?", 1)
        m = re.match(r"^([^@]+)@(\[?[^\]]+\]?):(\d+)$", body)
        if not m:
            return None
        uuid, host, port = m.group(1), m.group(2).strip("[]"), int(m.group(3))
        if not UUID_RE.match(uuid):
            return None
        if not (1 <= port <= 65535):
            return None
        if not host:
            return None
        try:
            ip = ipaddress.ip_address(host)
            if (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_unspecified):
                return None
        except ValueError:
            pass  # hostname, ok
        params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
        sec = params.get("security", "none")
        if sec == "reality":
            if len(params.get("pbk", "")) < 40 or not params.get("sni"):
                return None
        ntype = params.get("type", "tcp")
        if ntype == "raw":
            ntype = "tcp"
            params["type"] = "tcp"
        if ntype not in ("tcp", "ws", "grpc", "httpupgrade", "splithttp",
                         "xhttp"):
            return None
        key = f"{uuid}@{host}:{port}/{sec}/{ntype}"
        return {
            "uuid": uuid, "host": host, "port": port, "params": params,
            "remark": remark, "key": key, "security": sec, "ntype": ntype,
        }
    except Exception:
        return None


def tcp_check(host, port, timeout=4):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return int((time.time() - t0) * 1000)
    except Exception:
        return None


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------- xray real test ----------------

def build_xray_config(cfg, port):
    p = cfg["params"]
    user = {"id": cfg["uuid"],
            "encryption": p.get("encryption") or "none"}
    if p.get("flow"):
        user["flow"] = p["flow"]
    ss = {"network": cfg["ntype"], "security": cfg["security"]}
    if cfg["security"] == "tls":
        tls = {
            "serverName": p.get("sni") or cfg["host"],
            "fingerprint": p.get("fp", "chrome"),
        }
        if p.get("alpn"):
            tls["alpn"] = [x.strip() for x in p["alpn"].split(",") if x.strip()]
        ss["tlsSettings"] = tls
    elif cfg["security"] == "reality":
        ss["realitySettings"] = {
            "serverName": p.get("sni", ""),
            "fingerprint": p.get("fp", "chrome"),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", ""),
        }
    if cfg["ntype"] == "ws":
        ws = {"path": p.get("path", "/")}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        ss["wsSettings"] = ws
    elif cfg["ntype"] == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
        if p.get("mode"):
            ss["grpcSettings"]["multiMode"] = True
    elif cfg["ntype"] == "httpupgrade":
        hu = {"path": p.get("path", "/")}
        if p.get("host"):
            hu["headers"] = {"Host": p["host"]}
        ss["httpupgradeSettings"] = hu
    elif cfg["ntype"] == "splithttp":
        sh = {"path": p.get("path", "/")}
        if p.get("host"):
            sh["headers"] = {"Host": p["host"]}
        ss["splithttpSettings"] = sh
    elif cfg["ntype"] == "xhttp":
        xh = {"path": p.get("path", "/")}
        if p.get("host"):
            xh["headers"] = {"Host": p["host"]}
        if p.get("mode"):
            xh["mode"] = p["mode"]
        ss["xhttpSettings"] = xh
    elif cfg["ntype"] == "tcp" and p.get("headerType", "none") == "http":
        ss["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [p.get("path", "/")],
                    "headers": {"Host": [p.get("host") or cfg["host"]]},
                },
            }
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": port, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": cfg["host"], "port": cfg["port"], "users": [user],
            }]},
            "streamSettings": ss,
        }],
    }


def kill_proc(proc):
    try:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
    except Exception:
        pass


def curl_via(port, url, timeout=9, want_body=False):
    proxy = f"socks5h://127.0.0.1:{port}"
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        body_file = tf.name
    try:
        cmd = ["curl", "-s", "-o", body_file, "-w", "%{http_code} %{time_total}",
               "-x", proxy, "--max-time", str(timeout), url]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 6)
        if r.returncode != 0:
            return None
        parts = r.stdout.strip().split()
        if len(parts) != 2:
            return None
        code, t = int(parts[0]), float(parts[1])
        if code not in (200, 204):
            return None
        body = ""
        if want_body:
            try:
                with open(body_file, encoding="utf-8", errors="ignore") as f:
                    body = f.read(4000)
            except Exception:
                pass
        return {"ms": int(t * 1000), "body": body}
    except Exception:
        return None
    finally:
        try:
            os.unlink(body_file)
        except Exception:
            pass


def spawn_xray(cfg, port):
    conf = build_xray_config(cfg, port)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(conf, tf)
        cfile = tf.name
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfile],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        try:
            os.unlink(cfile)
        except Exception:
            pass
        return None, None
    time.sleep(1.5)
    if proc.poll() is not None:
        kill_proc(proc)
        try:
            os.unlink(cfile)
        except Exception:
            pass
        return None, None
    return proc, cfile


def run_xray_test(cfg, idx):
    port = 22000 + (idx % 200)
    proc, cfile = spawn_xray(cfg, port)
    if not proc:
        return None
    try:
        oks, bodies = [], []
        for i, url in enumerate(TARGETS):
            res = curl_via(port, url, timeout=9, want_body=(i > 0))
            if res:
                oks.append(res["ms"])
                if res["body"]:
                    bodies.append(res["body"])
        if len(oks) < 2:
            return None
        cc = ""
        for b in bodies:
            m = re.search(r"^loc=([A-Za-z]{2})$", b, re.M)
            if m:
                cc = m.group(1).upper()
                break
        return {"ping_ms": min(oks), "cc": cc}
    finally:
        kill_proc(proc)
        try:
            os.unlink(cfile)
        except Exception:
            pass


def test_one(cfg, idx):
    tcp_ms = tcp_check(cfg["host"], cfg["port"], timeout=4)
    if tcp_ms is None:
        return None
    res = run_xray_test(cfg, idx)
    if res is None:
        time.sleep(1)
        res = run_xray_test(cfg, idx + 1000)  # one retry, other port
    if res is None:
        return None
    res["tcp_ms"] = tcp_ms
    return res


def speed_one(cfg, idx):
    port = 23000 + (idx % 100)
    proc, cfile = spawn_xray(cfg, port)
    if not proc:
        return None
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w",
               "%{speed_download} %{size_download}",
               "-x", f"socks5h://127.0.0.1:{port}",
               "--max-time", "22", SPEED_URL]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=28)
        if r.returncode != 0:
            return None
        spd, size = r.stdout.strip().split()
        spd, size = float(spd), float(size)
        if size < 200000:
            return None
        return round(spd * 8 / 1e6, 1)
    except Exception:
        return None
    finally:
        kill_proc(proc)
        try:
            os.unlink(cfile)
        except Exception:
            pass


# ---------------- geo + ooni ----------------

def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return "🌐"
    cc = cc.upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def flag_from_remark(remark):
    m = re.search("([\U0001F1E6-\U0001F1FF]{2})", remark or "")
    return m.group(1) if m else ""


def ipapi_cc(host):
    try:
        raw = http_get(
            f"http://ip-api.com/json/{host}?fields=status,countryCode",
            timeout=8,
        )
        j = json.loads(raw.decode())
        if j.get("status") == "success" and j.get("countryCode"):
            return j["countryCode"]
    except Exception:
        pass
    return ""


def ooni_blocked(domain):
    """True if domain looks blocked in Iran per OONI data. False on any doubt."""
    try:
        q = urllib.parse.quote(f"https://{domain}/", safe="")
        raw = http_get(
            "https://api.ooni.io/api/v1/measurements"
            f"?probe_cc=IR&input={q}&limit=10&order_by=test_start_time",
            timeout=12,
        )
        items = json.loads(raw.decode()).get("results", [])
        if not items:
            return False
        conf = sum(1 for it in items if it.get("confirmed"))
        anom = sum(1 for it in items if it.get("anomaly"))
        if conf >= 1:
            return True
        if len(items) >= 3 and anom / len(items) >= 0.6:
            return True
        return False
    except Exception:
        return False


# ---------------- main ----------------

def main():
    t_start = time.time()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    chans, urls = load_sources()
    log(f"sources: {len(chans)} channels, {len(urls)} urls")
    raw_links = []
    for ch in chans:
        raw_links += fetch_channel(ch)
    for u in urls:
        raw_links += fetch_url_source(u)
    log(f"raw links: {len(raw_links)}")

    seen, cands, dups = set(), [], 0
    for link, src in raw_links:
        cfg = parse_vless(link)
        if not cfg:
            continue
        if cfg["key"] in seen:
            dups += 1
            continue
        seen.add(cfg["key"])
        cfg["src"] = src
        cands.append(cfg)
    log(f"valid unique: {len(cands)} (dups skipped: {dups})")

    prev = kv_get_prev()
    prev_map = {c.get("key"): c for c in prev.get("configs", [])}
    total_runs = (prev.get("total_runs") or 0) + 1

    # fresh configs first, then cap
    cands.sort(key=lambda c: (c["key"] in prev_map,))
    cands = cands[:CANDIDATE_CAP]

    passed, failed = [], 0
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=THREADS_TEST) as ex:
        futs = {ex.submit(test_one, c, i): c for i, c in enumerate(cands)}
        for f in concurrent.futures.as_completed(futs):
            c = futs[f]
            try:
                res = f.result()
            except Exception:
                res = None
            if res:
                c.update(res)
                passed.append(c)
            else:
                failed += 1
    log(f"real-test passed: {len(passed)}, failed: {failed}")
    passed.sort(key=lambda c: c["ping_ms"])

    # speed test for fastest subset
    for_spd = passed[:SPEED_CAP]
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=THREADS_SPEED) as ex:
        futs = {ex.submit(speed_one, c, i): c for i, c in enumerate(for_spd)}
        for f in concurrent.futures.as_completed(futs):
            try:
                futs[f]["speed_mbps"] = f.result()
            except Exception:
                futs[f]["speed_mbps"] = None
    for c in passed[SPEED_CAP:]:
        c["speed_mbps"] = None

    # geo: tunnel trace already gave cc for many; fill rest via ip-api/remark
    for c in passed[:40]:
        if not c.get("cc"):
            c["cc"] = ipapi_cc(c["host"]) or ""
        if not c.get("cc"):
            c["flag_only"] = flag_from_remark(c.get("remark", ""))

    # ooni iran check for unique domains
    doms = []
    for c in passed[:40]:
        d = c["host"]
        if not is_ip(d) and d not in doms:
            doms.append(d)
    blocked = set()
    for d in doms[:25]:
        if ooni_blocked(d):
            blocked.add(d)
            log(f"ooni: {d} looks blocked in IR, excluded")
    elig = [c for c in passed if c["host"] not in blocked]

    for c in elig:
        pc = prev_map.get(c["key"], {})
        c["consec"] = (pc.get("consec") or 0) + 1
    elig.sort(key=lambda c: (c["ping_ms"], -(c["speed_mbps"] or 0)))
    top = elig[:PUBLISH_COUNT]

    # anti-flap: keep previous payload if this run collapsed
    if len(top) < 3 and len(prev.get("configs", [])) >= 10:
        log("run collapsed, keeping previous payload")
        payload = prev
        payload["kept_previous"] = True
        payload["run_id"] = run_id
        payload["total_runs"] = total_runs
    else:
        runs_short = total_runs < 3
        fast = [c for c in top
                if (c["consec"] >= 2 or runs_short)][:FAST_COUNT]

        def transport_label(c):
            if c["security"] == "reality":
                return "Reality"
            return {"ws": "WS", "tcp": "TCP", "grpc": "gRPC",
                    "httpupgrade": "HU", "xhttp": "XHTTP",
                    "splithttp": "SH"}.get(c["ntype"], c["ntype"])

        def build_link(c):
            cc = c.get("cc") or ""
            flag = flag_emoji(cc) if cc else c.get("flag_only") or "🌐"
            spd = f"{c['speed_mbps']}M" if c.get("speed_mbps") else "—"
            label = transport_label(c)
            remark = f"{flag} {cc or 'UN'} | {c['ping_ms']}ms | ↓{spd} | {label}"
            q = urllib.parse.urlencode(c["params"])
            return (f"vless://{c['uuid']}@{c['host']}:{c['port']}?{q}"
                    f"#{urllib.parse.quote(remark, safe='')}")

        for c in top:
            c["link"] = build_link(c)
            c["transport"] = transport_label(c)
        fast_keys = {c["key"] for c in fast}
        payload = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "total_runs": total_runs,
            "seen": len(raw_links),
            "valid": len(cands),
            "passed": len(passed),
            "published": len(top),
            "fast_count": len(fast),
            "configs": [{
                k: c.get(k) for k in (
                    "key", "link", "ping_ms", "speed_mbps", "cc",
                    "transport", "consec")
            } for c in top],
            "fast_keys": sorted(fast_keys),
        }
        payload["sub_all"] = base64.b64encode(
            "\n".join(c["link"] for c in top).encode()).decode()
        payload["sub_fast"] = base64.b64encode(
            "\n".join(c["link"] for c in top
                      if c["key"] in fast_keys).encode()).decode()

        if CF_API_TOKEN and CF_ACCOUNT_ID and KV_NAMESPACE_ID:
            try:
                r = cf_put_kv("results:v1", json.dumps(payload).encode())
                log("KV push:", r.get("success"))
            except Exception as e:
                log("KV push failed:", e)
        else:
            log("KV creds missing, skipped push")

        if CF_API_TOKEN and CF_ACCOUNT_ID and D1_DATABASE_ID:
            try:
                with open(SCHEMA_FILE, encoding="utf-8") as f:
                    for stmt in f.read().split(";"):
                        stmt = stmt.strip()
                        if stmt:
                            cf_d1_query(stmt)
                ts = int(time.time())
                rows = [(c["key"], ts, 1, c["ping_ms"],
                         c.get("speed_mbps"), c.get("cc") or "",
                         c.get("transport") or "") for c in top]
                if rows:
                    ph = ",".join(["(?,?,?,?,?,?,?)"] * len(rows))
                    flat = [x for r in rows for x in r]
                    cf_d1_query(
                        "INSERT INTO history (cfg_key, ts, ok, ping_ms,"
                        f" speed_mbps, cc, transport) VALUES {ph}", flat)
                cf_d1_query("DELETE FROM history WHERE ts < ?",
                            [ts - 14 * 86400])
                log("D1 updated")
            except Exception as e:
                log("D1 failed:", e)
        payload["kept_previous"] = False

    stats = {
        "updated_at": payload.get("updated_at", ""),
        "run_id": run_id,
        "total_runs": total_runs,
        "sources": {"channels": chans, "urls": len(urls)},
        "seen": len(raw_links),
        "valid": len(cands),
        "passed": len(passed),
        "published": payload.get("published", 0),
        "fast": payload.get("fast_count", 0),
        "kept_previous": payload.get("kept_previous", False),
        "duration_s": int(time.time() - t_start),
        "summary": f"{payload.get('published', 0)}/{len(cands)} published",
    }
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    log("done in", stats["duration_s"], "s |", stats["summary"])


if __name__ == "__main__":
    main()
