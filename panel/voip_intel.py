#!/usr/bin/env python3
"""voip_intel.py — Threat-intelligence engine for the 3366 VoIP honeypot.

Standalone, stdlib-only, READ-ONLY companion to /opt/voip/app.py. It fuses every
signal the honeypot already produces — call recordings + their .meta/.analysis,
the pre-answer spam-gate events/decisions, and the FTC reputation feed — into
entity-centric intelligence (per-ANI, per-source-IP, per-DNI), scores indicators
of compromise with a transparent model, clusters campaigns, and exports the
result as CSV, JSON, STIX 2.1, a feedback blocklist, and a self-contained HTML
dashboard with trends.

It never writes into /opt/voip and never opens a network socket. Run it as a
user that can *read* the honeypot data (voip-panel or root); write outputs
somewhere else (default: ./intel-out).

  voip_intel.py --selftest                 # synthetic end-to-end validation
  voip_intel.py --since 30 --export all     # full run over the last 30 days
  voip_intel.py --since 7 --export dashboard,blocklist --min-score 70

Data schemas consumed (as emitted by app.py and spam_gate_3366.lua):
  recordings/3366_<YYYYMMDD>_<HHMMSS>_<ani>_<dni>_<uuid>.wav
  recordings/<same>.meta      JSON: media_ip, sig_ip, sip_code, sip_state,
                              sip_reason, hangup_cause, connected,
                              identity_header, verstat, pai_header
  recordings/<same>.analysis  JSON: risk_level, risk_score, red_flags[],
                              summary, azure{pii,sentiment,content_safety},
                              operational{score,level,components,findings}
  spam_events/<YYYYMMDD>.tsv    ts  ani  dni  sig_ip  uuid
  spam_decisions/<YYYYMMDD>.tsv ts  ani  dni  sig_ip  score  verdict  reasons
                               complaints  robocalls  last_seen  uuid
  spam_reputation_current/<ddd>.tsv  number  complaints  robocalls  last_seen
"""
import argparse, csv, html, io, ipaddress, json, math, os, re, sys, tempfile, time, uuid as _uuid
from collections import defaultdict

NAME_RE     = re.compile(r'^3366_(\d{8})_(\d{6})_([^_]+)_([^_]+)_([0-9a-fA-F-]{36})\.wav$')
NAME_RE_OLD = re.compile(r'^3366_(\d{8})_(\d{6})_(.+?)_([0-9a-fA-F-]{36})\.wav$')

# Verdicts the spam-gate emits, ordered by severity.
VERDICT_RANK = {"not_spam": 0, "trusted_excluded": 0, "spam_likely": 1,
                "high_risk": 2, "suspected_fraud": 3}
OP_LEVEL_RANK = {"low": 0, "moderate": 1, "high": 2, "critical": 3}


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def epoch_from_name(d, t):
    try:
        return time.mktime(time.strptime(d + t, "%Y%m%d%H%M%S"))
    except (ValueError, OverflowError):
        return 0.0


def day_key(epoch):
    return time.strftime("%Y-%m-%d", time.localtime(epoch)) if epoch else "unknown"


def clamp(n, lo=0, hi=100):
    return max(lo, min(hi, n))


def safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return {}


# ----------------------------------------------------------------------------
# loaders
# ----------------------------------------------------------------------------
def load_calls(data_dir, since_epoch):
    """One row per recording, joined with its .meta and .analysis sidecars."""
    rec_dir = os.path.join(data_dir, "recordings")
    calls = []
    try:
        names = os.listdir(rec_dir)
    except OSError:
        return calls
    for fn in names:
        if not fn.endswith(".wav"):
            continue
        ani = dni = "-"
        epoch = 0.0
        m = NAME_RE.match(fn)
        if m:
            d, t, ani, dni, uid = m.groups()
            epoch = epoch_from_name(d, t)
        else:
            mo = NAME_RE_OLD.match(fn)
            if not mo:
                continue
            d, t, dni, uid = mo.groups()
            epoch = epoch_from_name(d, t)
        if since_epoch and epoch and epoch < since_epoch:
            continue
        base = os.path.join(rec_dir, fn)
        try:
            size = os.path.getsize(base)
        except OSError:
            size = 0
        meta = _read_json(base[:-4] + ".meta")
        # Panel writes analyses to transcripts/analysis/<wav>.json; legacy .analysis kept as fallback.
        analysis = _read_json(os.path.join(data_dir, "transcripts", "analysis", fn + ".json")) or _read_json(base[:-4] + ".analysis")
        op = (analysis.get("operational") or {}) if isinstance(analysis, dict) else {}
        azure = (analysis.get("azure") or {}) if isinstance(analysis, dict) else {}
        cs = azure.get("content_safety") or {}
        pii = azure.get("pii") or {}
        calls.append({
            "file": fn, "uuid": uid, "epoch": epoch, "when": day_key(epoch),
            "ani": _norm_num(ani), "dni": _norm_num(dni), "size": size,
            "sig_ip": str(meta.get("sig_ip") or "-"),
            "media_ip": str(meta.get("media_ip") or "-"),
            "sip_code": str(meta.get("sip_code") or ""),
            "sip_reason": str(meta.get("sip_reason") or ""),
            "connected": bool(meta.get("connected")) if isinstance(meta.get("connected"), bool) else None,
            "stir": _stir_status(meta),
            "op_score": safe_int(op.get("score")),
            "op_level": str(op.get("level") or "low"),
            "content_score": safe_int(analysis.get("risk_score")) if isinstance(analysis, dict) else 0,
            "red_flags": [str(f.get("title") or "") for f in (analysis.get("red_flags") or [])] if isinstance(analysis, dict) else [],
            "pii_count": safe_int(pii.get("count")),
            "cs_max": safe_int(cs.get("max_severity")),
            "summary": str(analysis.get("summary") or "") if isinstance(analysis, dict) else "",
            "analyzed": bool(analysis),
        })
    return calls


def _norm_num(v):
    v = re.sub(r"[^0-9]", "", str(v or ""))
    return v or "-"


def _stir_status(meta):
    """Collapse signaling evidence to one of passed/failed/missing/unverified/legacy."""
    identity = str(meta.get("identity_header") or "").strip()
    verstat = str(meta.get("verstat") or "").strip().lower()
    pai = str(meta.get("pai_header") or "")
    if not verstat:
        mm = re.search(r"verstat=([^;>,\s]+)", pai, re.I)
        verstat = (mm.group(1).lower() if mm else "")
    captured = any(k in meta for k in ("identity_header", "verstat", "pai_header"))
    if "validation-passed" in verstat:
        return "passed"
    if "validation-failed" in verstat or "fail" in verstat:
        return "failed"
    if "no-tn-validation" in verstat:
        return "unverified"
    if identity:
        return "unverified"
    if captured:
        return "missing"
    return "legacy"


def load_decisions(data_dir, since_epoch):
    """Pre-answer spam-gate decisions — the honeypot's own real-time verdicts."""
    ddir = os.path.join(data_dir, "spam_decisions")
    rows = []
    try:
        files = sorted(os.listdir(ddir))
    except OSError:
        return rows
    for fn in files:
        if not fn.endswith(".tsv"):
            continue
        try:
            with open(os.path.join(ddir, fn), encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 6:
                        continue
                    ts = safe_int(parts[0])
                    if since_epoch and ts and ts < since_epoch:
                        continue
                    reasons = parts[6] if len(parts) > 6 else ""
                    rows.append({
                        "ts": ts, "ani": _norm_num(parts[1]), "dni": _norm_num(parts[2]),
                        "sig_ip": parts[3], "score": safe_int(parts[4]), "verdict": parts[5],
                        "reasons": [] if reasons in ("", "NONE") else reasons.split(","),
                        "complaints": safe_int(parts[7]) if len(parts) > 7 else 0,
                        "robocalls": safe_int(parts[8]) if len(parts) > 8 else 0,
                        "uuid": parts[11] if len(parts) > 11 else "",
                    })
        except OSError:
            continue
    return rows


def load_events(data_dir, since_epoch):
    """Raw pre-answer sightings (one line per attempt, even rejected ones)."""
    edir = os.path.join(data_dir, "spam_events")
    rows = []
    try:
        files = sorted(os.listdir(edir))
    except OSError:
        return rows
    for fn in files:
        if not fn.endswith(".tsv"):
            continue
        try:
            with open(os.path.join(edir, fn), encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 4:
                        continue
                    ts = safe_int(p[0])
                    if since_epoch and ts and ts < since_epoch:
                        continue
                    rows.append({"ts": ts, "ani": _norm_num(p[1]),
                                 "dni": _norm_num(p[2]), "sig_ip": p[3]})
        except OSError:
            continue
    return rows


def load_reputation(data_dir):
    """FTC DNC complaint reputation, keyed by full number."""
    rdir = os.path.join(data_dir, "spam_reputation_current")
    rep = {}
    try:
        files = os.listdir(rdir)
    except OSError:
        return rep
    for fn in files:
        if not fn.endswith(".tsv"):
            continue
        try:
            with open(os.path.join(rdir, fn), encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) >= 3 and p[0].isdigit():
                        rep[p[0]] = {"complaints": safe_int(p[1]),
                                     "robocalls": safe_int(p[2]),
                                     "last_seen": p[3] if len(p) > 3 else ""}
        except OSError:
            continue
    return rep


# ----------------------------------------------------------------------------
# entity aggregation + scoring
# ----------------------------------------------------------------------------
def _new_entity(kind, value):
    return {
        "kind": kind, "value": value, "calls": 0, "attempts": 0,
        "first_seen": None, "last_seen": None,
        "dnis": set(), "ips": set(), "anis": set(),
        "verdict_max": 0, "verdicts": defaultdict(int),
        "gate_score_max": 0, "op_score_max": 0, "op_level_max": 0,
        "content_score_max": 0, "cs_max": 0, "pii_calls": 0,
        "stir": defaultdict(int), "reasons": defaultdict(int),
        "red_flags": defaultdict(int), "complaints": 0, "robocalls": 0,
        "connected": 0, "recordings": [], "tags": [], "ts": [],
    }


def _touch_time(ent, ts):
    if not ts:
        return
    ent["first_seen"] = ts if ent["first_seen"] is None else min(ent["first_seen"], ts)
    ent["last_seen"] = ts if ent["last_seen"] is None else max(ent["last_seen"], ts)


def build_entities(calls, decisions, events, reputation):
    anis, ips, dnis = {}, {}, {}

    def ent(store, kind, value):
        if value in ("", "-", None):
            return None
        if value not in store:
            store[value] = _new_entity(kind, value)
        return store[value]

    # Pre-answer sightings (attempts) — includes calls that were rejected and
    # therefore never became recordings. This is the widest sensor.
    for e in events:
        for store, kind, val, peer_ip, peer_ani in (
            (anis, "ani", e["ani"], e["sig_ip"], None),
            (ips, "ipv4", e["sig_ip"], None, e["ani"]),
        ):
            a = ent(store, kind, val)
            if not a:
                continue
            a["attempts"] += 1
            _touch_time(a, e["ts"])
            if e["ts"] and len(a["ts"]) < 5000:
                a["ts"].append(e["ts"])
            if e["dni"] not in ("", "-"):
                a["dnis"].add(e["dni"])
            if kind == "ani" and peer_ip not in ("", "-", "unknown"):
                a["ips"].add(peer_ip)
            if kind == "ipv4" and peer_ani not in ("", "-"):
                a["anis"].add(peer_ani)

    # Real-time gate decisions.
    for d in decisions:
        for store, kind, val in ((anis, "ani", d["ani"]), (ips, "ipv4", d["sig_ip"])):
            a = ent(store, kind, val)
            if not a:
                continue
            _touch_time(a, d["ts"])
            a["verdicts"][d["verdict"]] += 1
            a["verdict_max"] = max(a["verdict_max"], VERDICT_RANK.get(d["verdict"], 0))
            a["gate_score_max"] = max(a["gate_score_max"], d["score"])
            a["complaints"] = max(a["complaints"], d["complaints"])
            a["robocalls"] = max(a["robocalls"], d["robocalls"])
            for r in d["reasons"]:
                a["reasons"][r] += 1

    # Post-answer recordings + analysis (the calls that got through).
    for c in calls:
        for store, kind, val, peer_ip, peer_ani in (
            (anis, "ani", c["ani"], c["sig_ip"], None),
            (ips, "ipv4", c["sig_ip"], None, c["ani"]),
            (dnis, "dni", c["dni"], None, c["ani"]),
        ):
            a = ent(store, kind, val)
            if not a:
                continue
            a["calls"] += 1
            _touch_time(a, c["epoch"])
            a["recordings"].append(c["file"])
            if c["dni"] not in ("", "-"):
                a["dnis"].add(c["dni"])
            if kind == "ani" and c["sig_ip"] not in ("", "-", "unknown"):
                a["ips"].add(c["sig_ip"])
            if kind in ("ipv4", "dni") and c["ani"] not in ("", "-"):
                a["anis"].add(c["ani"])
            a["op_score_max"] = max(a["op_score_max"], c["op_score"])
            a["op_level_max"] = max(a["op_level_max"], OP_LEVEL_RANK.get(c["op_level"], 0))
            a["content_score_max"] = max(a["content_score_max"], c["content_score"])
            a["cs_max"] = max(a["cs_max"], c["cs_max"])
            if c["pii_count"] > 0:
                a["pii_calls"] += 1
            if c["connected"]:
                a["connected"] += 1
            a["stir"][c["stir"]] += 1
            for rf in c["red_flags"]:
                if rf:
                    a["red_flags"][rf] += 1

    # FTC reputation overlay for ANIs.
    for value, a in anis.items():
        r = reputation.get(value)
        if r is None and len(value) == 11 and value.startswith("1"):
            r = reputation.get(value[1:])   # FTC list stores 10-digit national numbers
        elif r is None and len(value) == 10:
            r = reputation.get("1" + value)
        if r:
            a["complaints"] = max(a["complaints"], r["complaints"])
            a["robocalls"] = max(a["robocalls"], r["robocalls"])

    for store in (anis, ips, dnis):
        for a in store.values():
            score_entity(a)
    return {"ani": anis, "ipv4": ips, "dni": dnis}


def score_entity(a):
    """Transparent 0-100 threat score. Every point is attributable to a reason
    so the output is defensible, not a black box."""
    score, why = 0, []

    def add(pts, label):
        nonlocal score
        score += pts
        why.append({"points": pts, "label": label})

    # --- reputation (strongest external corroboration) ---
    if a["complaints"] > 0:
        add(35, f"FTC DNC complaint match ({a['complaints']})")
    if a["complaints"] >= 3:
        add(10, "Repeated FTC complaints")
    if a["robocalls"] > 0:
        add(10, "FTC robocall report")

    # --- real-time gate verdicts ---
    if a["verdict_max"] >= 3:
        add(30, "Gate verdict: suspected fraud")
    elif a["verdict_max"] == 2:
        add(20, "Gate verdict: high risk")
    elif a["verdict_max"] == 1:
        add(10, "Gate verdict: spam likely")
    if a["gate_score_max"] >= 85:
        add(10, f"Peak gate score {a['gate_score_max']}")

    # --- post-answer content analysis ---
    if a["op_level_max"] >= 3:
        add(25, "Analyzed call scored critical")
    elif a["op_level_max"] == 2:
        add(15, "Analyzed call scored high")
    if a["content_score_max"] >= 55:
        add(12, "Transcript fraud indicators")
    if a["cs_max"] >= 4:
        add(12, f"Harmful-content severity {a['cs_max']}/6")

    # --- identity ---
    if a["stir"].get("failed"):
        add(20, "STIR/SHAKEN verification failed")
    elif a["stir"].get("missing"):
        add(6, "STIR/SHAKEN identity missing")

    # --- behaviour ---
    dni_n, ip_n, ani_n = len(a["dnis"]), len(a["ips"]), len(a["anis"])
    if a["kind"] == "ani":
        if dni_n >= 10:
            add(15, f"Swept {dni_n} distinct DNIs")
        elif dni_n >= 4:
            add(8, f"Swept {dni_n} distinct DNIs")
        if ip_n >= 3:
            add(10, f"Seen from {ip_n} source IPs (possible spoofing infra)")
    if a["kind"] == "ipv4":
        # One IP presenting many caller-IDs is the classic spoofing/gateway signal.
        if ani_n >= 20:
            add(25, f"{ani_n} distinct caller-IDs from one IP")
        elif ani_n >= 8:
            add(15, f"{ani_n} distinct caller-IDs from one IP")
        elif ani_n >= 3:
            add(8, f"{ani_n} distinct caller-IDs from one IP")
        if dni_n >= 20:
            add(10, f"Targeted {dni_n} honeypot numbers")
    volume = a["attempts"] + a["calls"]
    if volume >= 50:
        add(10, f"High volume ({volume} attempts)")
    elif volume >= 15:
        add(5, f"Elevated volume ({volume} attempts)")
    if "INVALID_ANI_FORMAT" in a["reasons"] or (a["kind"] == "ani" and not a["value"].isdigit()):
        add(6, "Invalid/malformed caller-ID")

    a["threat_score"] = clamp(score)
    a["level"] = ("critical" if a["threat_score"] >= 70 else "high" if a["threat_score"] >= 45
                  else "medium" if a["threat_score"] >= 20 else "low")
    # Confidence rises with the number of independent corroborating sensor types.
    sensors = sum(bool(x) for x in (
        a["complaints"], a["verdict_max"], a["op_level_max"] or a["content_score_max"],
        a["stir"].get("failed"), volume >= 15))
    a["confidence"] = ("high" if sensors >= 3 else "medium" if sensors == 2 else "low")
    a["why"] = sorted(why, key=lambda w: w["points"], reverse=True)
    return a


# ----------------------------------------------------------------------------
# campaign clustering
# ----------------------------------------------------------------------------
def build_campaigns(events, decisions, window=900, min_size=5, trunks=None):
    """A campaign = a burst of attempts from one *non-trunk* source IP inside a
    sliding window. Bursts are how sweeps/robocall runs look on the wire; the
    carrier ingress trunk is infrastructure and is excluded."""
    trunks = set(trunks or ())
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["sig_ip"]].append((e["ts"], e["ani"], e["dni"]))
    for d in decisions:  # decisions may cover rejected attempts not in events
        by_ip[d["sig_ip"]].append((d["ts"], d["ani"], d["dni"]))
    verdict_by_ip = defaultdict(int)
    for d in decisions:
        verdict_by_ip[d["sig_ip"]] = max(verdict_by_ip[d["sig_ip"]],
                                         VERDICT_RANK.get(d["verdict"], 0))
    campaigns = []
    for ip, rows in by_ip.items():
        if ip in ("", "-", "unknown") or ip in trunks:
            continue
        rows.sort(key=lambda r: r[0] or 0)
        cluster = []
        def flush():
            if len(cluster) < min_size:
                return
            ts0, ts1 = cluster[0][0], cluster[-1][0]
            anis = {r[1] for r in cluster if r[1] not in ("", "-")}
            dnis = {r[2] for r in cluster if r[2] not in ("", "-")}
            span = max(1, (ts1 or 0) - (ts0 or 0))
            campaigns.append({
                "id": "campaign--" + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, f"{ip}:{ts0}")),
                "source_ip": ip, "attempts": len(cluster),
                "unique_anis": len(anis), "unique_dnis": len(dnis),
                "start": ts0, "end": ts1, "span_seconds": span,
                "rate_per_min": round(len(cluster) / (span / 60.0), 2) if span else len(cluster),
                "verdict_rank": verdict_by_ip.get(ip, 0),
                "sample_anis": sorted(anis)[:10],
            })
        for row in rows:
            if cluster and row[0] and cluster[-1][0] and row[0] - cluster[-1][0] > window:
                flush()
                cluster = []
            cluster.append(row)
        flush()
    campaigns.sort(key=lambda c: (c["verdict_rank"], c["attempts"]), reverse=True)
    return campaigns


# ----------------------------------------------------------------------------
# trends
# ----------------------------------------------------------------------------
def build_trends(calls, decisions, events):
    days = defaultdict(lambda: {"attempts": 0, "recorded": 0, "blocked": 0,
                                "allowed": 0, "anis": set(), "ips": set(),
                                "critical": 0, "high": 0})
    for e in events:
        days[day_key(e["ts"])]["attempts"] += 1
        days[day_key(e["ts"])]["anis"].add(e["ani"])
        days[day_key(e["ts"])]["ips"].add(e["sig_ip"])
    for d in decisions:
        k = day_key(d["ts"])
        blocked = d["verdict"] not in ("not_spam", "trusted_excluded") and d["score"] >= 50
        days[k]["blocked" if blocked else "allowed"] += 1
    for c in calls:
        k = c["when"]
        days[k]["recorded"] += 1
        if c["op_level"] == "critical":
            days[k]["critical"] += 1
        elif c["op_level"] == "high":
            days[k]["high"] += 1
    out = []
    for k in sorted(days):
        if k == "unknown":
            continue
        v = days[k]
        out.append({"date": k, "attempts": v["attempts"], "recorded": v["recorded"],
                    "blocked": v["blocked"], "allowed": v["allowed"],
                    "unique_anis": len(v["anis"]), "unique_ips": len(v["ips"]),
                    "critical": v["critical"], "high": v["high"]})
    return out


# ----------------------------------------------------------------------------
# advanced signals: spoofing fingerprints, bot cadence, subnet correlation
# ----------------------------------------------------------------------------
TOLL_FREE_NPA = {"800", "888", "877", "866", "855", "844", "833", "822"}


def _digit_runs_sequential(nums):
    """Count how many numbers form a consecutive ±1 run — the signature of an
    IP enumerating spoofed caller-IDs (…000, …001, …002)."""
    vals = sorted({int(n) for n in nums if n.isdigit() and len(n) <= 18})
    if len(vals) < 3:
        return 0
    best = run = 1
    for i in range(1, len(vals)):
        run = run + 1 if vals[i] - vals[i - 1] == 1 else 1
        best = max(best, run)
    return best


def _npa(digits):
    """Return the 3-digit North American area code, tolerating a leading 1."""
    if len(digits) == 11 and digits[0] == "1":
        return digits[1:4]
    if len(digits) == 10:
        return digits[0:3]
    return ""


def _national10(digits):
    """The 10-digit national number (drops a leading country-code 1)."""
    if len(digits) == 11 and digits[0] == "1":
        return digits[1:]
    return digits


def _cadence_regularity(ts):
    """Coefficient of variation of inter-arrival gaps *within active bursts*.
    Idle gaps between dialing sessions are excluded so multi-day history does
    not mask machine-regular pacing. Very low CoV = autodialer/beacon."""
    ts = sorted(t for t in ts if t)
    if len(ts) < 8:
        return None, 0
    gaps = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
    gaps = [g for g in gaps if 0 <= g <= 1800]  # drop inter-session idle gaps
    if len(gaps) < 7:
        return None, 0
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return None, len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return (var ** 0.5) / mean, len(gaps)


def _tag(a, label, points, reason):
    if label not in a["tags"]:
        a["tags"].append(label)
    a["threat_score"] = clamp(a["threat_score"] + points)
    a["why"].insert(0, {"points": points, "label": reason})


def load_trunks(data_dir):
    """Operator-declared trunk/trusted IPs: the spam-gate allow-list plus the
    configured termination vendor. Calls arrive from the carrier's SBC, so these
    are infrastructure, never threats — they must not be scored or blocklisted."""
    trunks = set()
    for line in _read_lines(os.path.join(data_dir, "spam_allow_ip.txt")):
        trunks.add(line)
    for path in ("vendor_3366.conf",):
        for line in _read_lines(os.path.join(data_dir, path)):
            trunks.add(line.split(":", 1)[0].strip())
    return {t for t in trunks if t}


def _read_lines(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
    except OSError:
        pass
    return out


def advanced_signals(entities, trunks=None, total_volume=0):
    """Second-pass enrichment that runs after base scoring: identifies ingress
    trunks (so infrastructure is never mistaken for a threat), adds spoofing /
    automation fingerprints as tags, and rolls IPs into /24 network blocks.

    On a honeypot every call enters through one or a few carrier trunks, so an
    IP that carries the dominant share of traffic — or is operator-declared —
    is labelled INGRESS-TRUNK, excluded from scoring, indicators and blocklists,
    and the spoofing story is told through the caller-IDs (ANIs) instead."""
    anis, ips = entities["ani"], entities["ipv4"]
    trunks = set(trunks or ())

    # Flag trunks first so their spoofing patterns are not scored as threats.
    for value, a in ips.items():
        volume = a["attempts"] + a["calls"]
        is_declared = value in trunks
        is_dominant = total_volume and volume >= 0.5 * total_volume and len(a["anis"]) >= 50
        if is_declared or is_dominant:
            a["trunk"] = True
            a["tags"] = ["INGRESS-TRUNK"]
            a["threat_score"] = 0
            a["level"] = "low"
            a["why"] = [{"points": 0, "label": "Operator-declared carrier trunk" if is_declared
                         else "Dominant-traffic ingress trunk (%d caller-IDs)" % len(a["anis"])}]

    for value, a in anis.items():
        digits = value if value.isdigit() else ""
        # Toll-free number presented as the *originator* of mass calls.
        if _npa(digits) in TOLL_FREE_NPA and (a["attempts"] + a["calls"]) >= 3:
            _tag(a, "TOLLFREE-ORIGIN", 8, "Toll-free number presented as mass originator")
        # Caller-ID reflecting the honeypot's own range (spoofed self / test dialer).
        if digits.startswith("3366"):
            _tag(a, "REFLECTION", 10, "Caller-ID reflects honeypot number range")
        # Structurally fake caller-IDs.
        if digits and len(set(digits)) <= 2 and len(digits) >= 7:
            _tag(a, "REPEATED-DIGITS", 8, "Structurally fake caller-ID (repeated digits)")
        if digits and (len(digits) < 10 or len(digits) > 15):
            _tag(a, "MALFORMED", 6, "Malformed caller-ID length")
        cov, samples = _cadence_regularity(a["ts"])
        if cov is not None and cov < 0.15 and samples >= 10:
            _tag(a, "BOT-CADENCE", 10, "Machine-regular call pacing (autodialer)")

    for value, a in ips.items():
        if a.get("trunk"):
            continue
        callerids = [x for x in a["anis"] if x not in ("", "-")]
        # Sequential enumeration of caller-IDs from one source IP.
        seqrun = _digit_runs_sequential(callerids)
        if seqrun >= 5:
            _tag(a, "SEQUENTIAL-ANI", 25, "%d sequentially-numbered caller-IDs (spoof enumeration)" % seqrun)
        elif seqrun >= 3:
            _tag(a, "SEQUENTIAL-ANI", 12, "%d sequentially-numbered caller-IDs" % seqrun)
        # Many caller-IDs sharing one NPA-NXX block = spoofing from a number block.
        blocks = defaultdict(int)
        for c in callerids:
            if c.isdigit() and len(c) >= 10:
                blocks[_national10(c)[:6]] += 1  # NPA-NXX of the national number
        top_block = max(blocks.values()) if blocks else 0
        if top_block >= 6:
            _tag(a, "BLOCK-SPOOF", 15, "%d caller-IDs share one NPA-NXX block" % top_block)
        cov, samples = _cadence_regularity(a["ts"])
        if cov is not None and cov < 0.12 and samples >= 12:
            _tag(a, "BOT-CADENCE", 12, "Machine-regular pacing from this source IP")

    # Global sequential-enumeration pass. On a single-trunk honeypot the whole
    # flood shares one source IP, so per-IP detection misses it — instead look
    # for consecutively-numbered caller-IDs across the entire population, which
    # is the fingerprint of an autodialer walking a spoofed number range. Runs
    # of >=4 consecutive integers do not occur by chance among real caller-IDs.
    numeric = sorted((int(_national10(v)), v) for v in anis if v.isdigit() and 10 <= len(_national10(v)) <= 11)
    i = 0
    while i < len(numeric):
        j = i
        while j + 1 < len(numeric) and numeric[j + 1][0] - numeric[j][0] == 1:
            j += 1
        runlen = j - i + 1
        if runlen >= 4:
            for _, v in numeric[i:j + 1]:
                _tag(anis[v], "SEQUENTIAL-ANI", 14, "Part of a %d-long sequential caller-ID range (spoof enumeration)" % runlen)
        i = j + 1

    # /24 subnet rollup — distributed infrastructure across nearby IPs.
    nets = defaultdict(lambda: {"ips": set(), "callerids": set(), "attempts": 0,
                                "calls": 0, "max_score": 0})
    for value, a in ips.items():
        if a.get("trunk"):
            continue
        try:
            net = str(ipaddress.ip_network(value + "/24", strict=False).network_address) + "/24"
        except ValueError:
            continue
        n = nets[net]
        n["ips"].add(value)
        n["callerids"] |= set(x for x in a["anis"] if x not in ("", "-"))
        n["attempts"] += a["attempts"]
        n["calls"] += a["calls"]
        n["max_score"] = max(n["max_score"], a["threat_score"])
    subnets = []
    for net, n in nets.items():
        if len(n["ips"]) < 2:  # only surface blocks with multiple live IPs
            continue
        subnets.append({
            "subnet": net, "ips": len(n["ips"]), "caller_ids": len(n["callerids"]),
            "attempts": n["attempts"] + n["calls"], "max_score": n["max_score"],
            "level": ("critical" if n["max_score"] >= 70 else "high" if n["max_score"] >= 45
                      else "medium" if n["max_score"] >= 20 else "low")})
    subnets.sort(key=lambda s: (s["ips"], s["max_score"]), reverse=True)
    trunk_ips = {v for v, a in ips.items() if a.get("trunk")}
    return {"subnets": subnets, "trunks": trunk_ips}


# ----------------------------------------------------------------------------
# assemble the intel report
# ----------------------------------------------------------------------------
def build_report(data_dir, since_days, min_score):
    since_epoch = time.time() - since_days * 86400 if since_days else 0
    calls = load_calls(data_dir, since_epoch)
    decisions = load_decisions(data_dir, since_epoch)
    events = load_events(data_dir, since_epoch)
    reputation = load_reputation(data_dir)
    entities = build_entities(calls, decisions, events, reputation)
    total_volume = len(events) + len(calls)
    trunks = load_trunks(data_dir)
    advanced = advanced_signals(entities, trunks, total_volume)  # trunk-aware enrichment
    campaigns = build_campaigns(events, decisions, trunks=advanced["trunks"])
    trends = build_trends(calls, decisions, events)

    def top(store):
        return sorted(store.values(), key=lambda a: (a["threat_score"], a["calls"] + a["attempts"]),
                      reverse=True)

    top_anis = top(entities["ani"])
    top_ips = top(entities["ipv4"])
    indicators = [a for a in (top_anis + top_ips)
                  if a["threat_score"] >= min_score and not a.get("trunk")]
    indicators.sort(key=lambda a: a["threat_score"], reverse=True)

    summary = {
        "generated_at": int(time.time()),
        "window_days": since_days,
        "total_attempts": len(events),
        "total_recordings": len(calls),
        "analyzed_recordings": sum(1 for c in calls if c["analyzed"]),
        "unique_anis": len(entities["ani"]),
        "unique_source_ips": len(entities["ipv4"]),
        "unique_dnis": len(entities["dni"]),
        "blocked_decisions": sum(1 for d in decisions
                                 if d["verdict"] not in ("not_spam", "trusted_excluded") and d["score"] >= 50),
        "indicators": len(indicators),
        "critical_indicators": sum(1 for a in indicators if a["level"] == "critical"),
        "spoofing_indicators": sum(1 for a in (top_anis + top_ips)
                                   if any(t in ("SEQUENTIAL-ANI", "BLOCK-SPOOF", "REFLECTION",
                                                "REPEATED-DIGITS", "TOLLFREE-ORIGIN") for t in a["tags"])),
        "bot_cadence_indicators": sum(1 for a in (top_anis + top_ips) if "BOT-CADENCE" in a["tags"]),
        "campaigns": len(campaigns),
        "subnets": len(advanced["subnets"]),
        "min_score": min_score,
    }
    return {"summary": summary, "entities": entities, "top_anis": top_anis,
            "top_ips": top_ips, "indicators": indicators, "campaigns": campaigns,
            "trends": trends, "calls": calls, "subnets": advanced["subnets"]}


# ----------------------------------------------------------------------------
# serialization helpers
# ----------------------------------------------------------------------------
def _ent_public(a, limit_why=8):
    return {
        "type": a["kind"], "indicator": a["value"], "threat_score": a["threat_score"],
        "level": a["level"], "confidence": a["confidence"],
        "first_seen": _iso(a["first_seen"]), "last_seen": _iso(a["last_seen"]),
        "attempts": a["attempts"], "recorded_calls": a["calls"],
        "distinct_dnis": len(a["dnis"]), "distinct_source_ips": len(a["ips"]),
        "distinct_caller_ids": len(a["anis"]),
        "ftc_complaints": a["complaints"], "ftc_robocalls": a["robocalls"],
        "peak_gate_score": a["gate_score_max"], "peak_op_score": a["op_score_max"],
        "stir": dict(a["stir"]), "top_verdicts": dict(a["verdicts"]),
        "top_reasons": _topk(a["reasons"], 6),
        "top_red_flags": _topk(a["red_flags"], 6),
        "tags": list(a.get("tags") or []),
        "trunk": bool(a.get("trunk")),
        "reasons": a["why"][:limit_why],
    }


def _topk(counter, k):
    return [{"name": n, "count": c} for n, c in
            sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:k]]


def _iso(epoch):
    if not epoch:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


# ----------------------------------------------------------------------------
# exporters
# ----------------------------------------------------------------------------
def export_json(report, path):
    payload = {
        "schema": "voip-honeypot-intel/1",
        "summary": report["summary"],
        "indicators": [_ent_public(a) for a in report["indicators"]],
        "top_anis": [_ent_public(a) for a in report["top_anis"][:100]],
        "top_source_ips": [_ent_public(a) for a in report["top_ips"][:100]],
        "campaigns": [dict(c, start=_iso(c["start"]), end=_iso(c["end"])) for c in report["campaigns"][:200]],
        "trends": report["trends"],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def export_csv(report, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["indicator", "type", "threat_score", "level", "confidence",
                    "first_seen", "last_seen", "attempts", "recorded_calls",
                    "distinct_dnis", "distinct_source_ips", "distinct_caller_ids",
                    "ftc_complaints", "ftc_robocalls", "peak_gate_score",
                    "top_verdict", "tags", "top_reasons"])
        for a in report["indicators"]:
            tv = max(a["verdicts"].items(), key=lambda kv: kv[1])[0] if a["verdicts"] else ""
            w.writerow([a["value"], a["kind"], a["threat_score"], a["level"], a["confidence"],
                        _iso(a["first_seen"]), _iso(a["last_seen"]), a["attempts"], a["calls"],
                        len(a["dnis"]), len(a["ips"]), len(a["anis"]),
                        a["complaints"], a["robocalls"], a["gate_score_max"], tv,
                        "|".join(a.get("tags") or []),
                        "; ".join(r["name"] for r in _topk(a["reasons"], 4))])
    return path


def export_stix(report, path):
    """STIX 2.1 bundle: one Indicator per scored IOC, plus Campaign SDOs. Uses
    the standard phone-number / ipv4-addr STIX patterning so any TIP can ingest."""
    now = _iso(time.time())
    objects = []
    ident_id = "identity--" + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, "voip-honeypot-3366"))
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": ident_id,
        "created": now, "modified": now, "name": "VoIP Honeypot 3366",
        "identity_class": "system", "sectors": ["telecommunications"],
        "description": "Autonomous SIP honeypot; indicators derived from observed abuse.",
    })
    conf = {"low": 15, "medium": 50, "high": 85}
    for a in report["indicators"]:
        if a["kind"] == "ani":
            pattern = "[phone-number:value = '%s']" % a["value"].replace("'", "")
            labels = ["fraudulent-caller-id"]
        else:
            pattern = "[ipv4-addr:value = '%s']" % a["value"].replace("'", "")
            labels = ["malicious-sip-source"]
        ind_id = "indicator--" + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, a["kind"] + ":" + a["value"]))
        obj = {
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now, "created_by_ref": ident_id,
            "name": "%s %s (threat %d)" % (a["kind"].upper(), a["value"], a["threat_score"]),
            "description": "; ".join(r["label"] for r in a["why"][:6]),
            "indicator_types": ["malicious-activity"], "pattern_type": "stix",
            "pattern": pattern, "valid_from": _iso(a["first_seen"]) or now,
            "confidence": conf.get(a["confidence"], 30),
            "labels": labels + [t.lower() for t in (a.get("tags") or [])],
            "external_references": ([{"source_name": "FTC-DNC",
                                      "description": "%d complaint(s), %d robocall report(s)" % (a["complaints"], a["robocalls"])}]
                                    if a["complaints"] else []),
            "x_threat_score": a["threat_score"], "x_level": a["level"],
            "x_attempts": a["attempts"], "x_recorded_calls": a["calls"],
        }
        objects.append(obj)
    for c in report["campaigns"][:100]:
        objects.append({
            "type": "campaign", "spec_version": "2.1", "id": c["id"],
            "created": now, "modified": now, "created_by_ref": ident_id,
            "name": "Burst from %s" % c["source_ip"],
            "description": "%d attempts, %d caller-IDs, %d target numbers at %.1f/min" % (
                c["attempts"], c["unique_anis"], c["unique_dnis"], c["rate_per_min"]),
            "first_seen": _iso(c["start"]) or now, "last_seen": _iso(c["end"]) or now,
        })
    bundle = {"type": "bundle", "id": "bundle--" + str(_uuid.uuid4()), "objects": objects}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    return path


def export_blocklist(report, path_ani, path_ip, min_score):
    """Feedback loop: emit force-lists in the exact format the spam-gate reads
    (spam_force_ani.txt / spam_force_ip.txt). Review before copying into prod."""
    stamp = _iso(time.time())
    with open(path_ani, "w", encoding="utf-8") as f:
        f.write("# voip_intel force-ANI candidates — generated %s (score >= %d)\n" % (stamp, min_score))
        f.write("# Review before deploying to /opt/voip/spam_force_ani.txt\n")
        for a in report["top_anis"]:
            if a["threat_score"] >= min_score and a["value"].isdigit():
                f.write("%s  # score=%d %s\n" % (a["value"], a["threat_score"],
                        ",".join(r["name"] for r in _topk(a["reasons"], 3))))
    with open(path_ip, "w", encoding="utf-8") as f:
        f.write("# voip_intel force-IP candidates — generated %s (score >= %d)\n" % (stamp, min_score))
        f.write("# Review before deploying to /opt/voip/spam_force_ip.txt\n")
        for a in report["top_ips"]:
            if (a["threat_score"] >= min_score and not a.get("trunk")
                    and a["value"] not in ("", "-", "unknown")):
                f.write("%s  # score=%d %s\n" % (a["value"], a["threat_score"],
                        ",".join(r["name"] for r in _topk(a["reasons"], 3))))
    return path_ani, path_ip


# ----------------------------------------------------------------------------
# dashboard (self-contained, theme-aware, no external assets)
# ----------------------------------------------------------------------------
def _svg_trend(trends):
    if not trends:
        return '<p class="muted">No trend data yet.</p>'
    trends = trends[-30:]
    w, h, pad = 720, 200, 28
    maxv = max([max(t["attempts"], t["recorded"], t["blocked"]) for t in trends] + [1])
    n = len(trends)
    step = (w - 2 * pad) / max(1, n - 1) if n > 1 else 0

    def pts(key):
        out = []
        for i, t in enumerate(trends):
            x = pad + i * step
            y = h - pad - (t[key] / maxv) * (h - 2 * pad)
            out.append("%.1f,%.1f" % (x, y))
        return " ".join(out)
    bars = ""
    bw = max(2, step * 0.5) if n > 1 else 20
    for i, t in enumerate(trends):
        x = pad + i * step - bw / 2
        bh = (t["blocked"] / maxv) * (h - 2 * pad)
        bars += '<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="var(--danger)" opacity="0.28"/>' % (
            x, h - pad - bh, bw, bh)
    grid = ""
    for g in range(1, 4):
        y = pad + (h - 2 * pad) * g / 4
        grid += '<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="var(--border)" stroke-width="1"/>' % (pad, y, w - pad, y)
    first, last = trends[0]["date"][5:], trends[-1]["date"][5:]
    return ('<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="Attempts, recordings and blocks per day">'
            '%s<polyline fill="none" stroke="var(--accent)" stroke-width="2.5" points="%s"/>'
            '<polyline fill="none" stroke="var(--ok)" stroke-width="2" points="%s"/>'
            '<text x="%d" y="%d" fill="var(--muted)" font-size="11">%s</text>'
            '<text x="%d" y="%d" fill="var(--muted)" font-size="11" text-anchor="end">%s</text>'
            '<text x="%d" y="14" fill="var(--muted)" font-size="11">peak %d/day</text></svg>'
            % (w, h, grid, pts("attempts"), pts("recorded"),
               pad, h - 8, first, w - pad, h - 8, last, pad, maxv))


def _rows_ent(entities, limit=25):
    rows = ""
    for a in entities[:limit]:
        badge = a["level"]
        why = html.escape("; ".join(r["label"] for r in a["why"][:4]))
        rows += (
            '<tr><td class="mono">%s</td><td><span class="pill %s">%d</span></td>'
            '<td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d/%d</td><td class="why">%s</td></tr>'
            % (html.escape(a["value"]), badge, a["threat_score"], a["confidence"],
               a["attempts"], a["calls"], len(a["dnis"]),
               a["complaints"], a["robocalls"], why))
    return rows or '<tr><td colspan="8" class="muted">Nothing above threshold.</td></tr>'


def export_dashboard(report, path):
    s = report["summary"]
    camp_rows = ""
    for c in report["campaigns"][:12]:
        camp_rows += ('<tr><td class="mono">%s</td><td>%d</td><td>%d</td><td>%d</td>'
                      '<td>%.1f/min</td><td>%s → %s</td></tr>' % (
                          html.escape(c["source_ip"]), c["attempts"], c["unique_anis"],
                          c["unique_dnis"], c["rate_per_min"],
                          _iso(c["start"])[5:16], _iso(c["end"])[11:16]))
    camp_rows = camp_rows or '<tr><td colspan="6" class="muted">No burst campaigns detected.</td></tr>'
    kpis = [
        ("Attempts (window)", s["total_attempts"]),
        ("Recordings", s["total_recordings"]),
        ("Blocked at gate", s["blocked_decisions"]),
        ("Unique caller-IDs", s["unique_anis"]),
        ("Unique source IPs", s["unique_source_ips"]),
        ("Scored indicators", s["indicators"]),
        ("Critical indicators", s["critical_indicators"]),
        ("Campaigns", s["campaigns"]),
    ]
    kpi_html = "".join(
        '<div class="kpi"><div class="kpi-v">%s</div><div class="kpi-l">%s</div></div>' % (v, html.escape(l))
        for l, v in kpis)
    doc = HTML_TEMPLATE.format(
        generated=_iso(s["generated_at"]), window=s["window_days"] or "all",
        kpis=kpi_html, trend=_svg_trend(report["trends"]),
        ani_rows=_rows_ent(report["top_anis"]), ip_rows=_rows_ent(report["top_ips"]),
        camp_rows=camp_rows, min_score=s["min_score"])
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


HTML_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoIP Honeypot — Threat Intelligence</title>
<style>
:root{{--bg:#f6f7f9;--panel:#fff;--ink:#1a1d21;--muted:#6b7280;--border:#e5e7eb;
--accent:#2563eb;--ok:#16a34a;--danger:#dc2626;--crit:#b91c1c;--high:#ea580c;
--med:#ca8a04;--low:#64748b;}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0e1116;--panel:#161b22;--ink:#e6edf3;
--muted:#8b949e;--border:#30363d;--accent:#58a6ff;--ok:#3fb950;--danger:#f85149;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:24px}}
h1{{font-size:22px;margin:0 0 2px}}.sub{{color:var(--muted);font-size:13px;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}}
.kpi{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}}
.kpi-v{{font-size:26px;font-weight:700}}.kpi-l{{color:var(--muted);font-size:12px;margin-top:2px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:20px}}
.card h2{{font-size:15px;margin:0 0 12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.03em}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.why{{color:var(--muted);font-size:12px;max-width:320px}}
.muted{{color:var(--muted)}}
.pill{{display:inline-block;min-width:34px;text-align:center;padding:2px 8px;border-radius:999px;
color:#fff;font-weight:700;font-size:12px}}
.pill.critical{{background:var(--crit)}}.pill.high{{background:var(--high)}}
.pill.medium{{background:var(--med)}}.pill.low{{background:var(--low)}}
.legend{{font-size:12px;color:var(--muted);margin-top:8px}}
.legend b{{color:var(--accent)}}.legend i{{color:var(--ok);font-style:normal}}
.two{{display:grid;grid-template-columns:1fr;gap:20px}}
@media(min-width:820px){{.two{{grid-template-columns:1fr 1fr}}}}
.overflow{{overflow-x:auto}}
</style></head><body><div class="wrap">
<h1>VoIP Honeypot — Threat Intelligence</h1>
<div class="sub">Generated {generated} · window: last {window} days · indicator threshold: score ≥ {min_score}</div>
<div class="grid">{kpis}</div>
<div class="card"><h2>Activity trend (last 30 days)</h2>{trend}
<div class="legend"><b>— attempts</b> · <i>— recordings</i> · <span style="color:var(--danger)">▮ blocked at gate</span></div></div>
<div class="two">
<div class="card"><h2>Top caller-IDs (ANI)</h2><div class="overflow"><table>
<tr><th>Caller-ID</th><th>Score</th><th>Conf</th><th>Att</th><th>Rec</th><th>DNIs</th><th>FTC c/r</th><th>Why</th></tr>
{ani_rows}</table></div></div>
<div class="card"><h2>Top source IPs</h2><div class="overflow"><table>
<tr><th>Source IP</th><th>Score</th><th>Conf</th><th>Att</th><th>Rec</th><th>DNIs</th><th>FTC c/r</th><th>Why</th></tr>
{ip_rows}</table></div></div>
</div>
<div class="card"><h2>Burst campaigns</h2><div class="overflow"><table>
<tr><th>Source IP</th><th>Attempts</th><th>Caller-IDs</th><th>Targets</th><th>Rate</th><th>Window</th></tr>
{camp_rows}</table></div></div>
<div class="sub">Operational screening indicators derived from observed honeypot traffic — not a legal determination or FCC certification.</div>
</div></body></html>"""


# ----------------------------------------------------------------------------
# self-test (synthetic data → full pipeline → exports)
# ----------------------------------------------------------------------------
def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def make_synthetic(root):
    for sub in ("recordings", "spam_events", "spam_decisions", "spam_reputation_current"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    base = time.time() - 3 * 86400
    # A clear fraud actor: one IP, many spoofed ANIs, DNI sweep, FTC hits.
    bad_ip = "203.0.113.45"
    for day in range(3):
        d = time.strftime("%Y%m%d", time.localtime(base + day * 86400))
        ev, dec = [], []
        for i in range(18):
            ts = int(base + day * 86400 + i * 20)
            ani = "1800%07d" % (5550000 + i)
            dni = "3366%04d" % (1000 + i)
            uid = str(_uuid.uuid4())
            ev.append("\t".join([str(ts), ani, dni, bad_ip, uid]))
            score = 90
            dec.append("\t".join([str(ts), ani, dni, bad_ip, str(score), "suspected_fraud",
                                  "HIGH_ANI_VELOCITY,DNI_SWEEP,STIR_VERIFICATION_FAILED",
                                  "2", "1", "2026-08-01", uid]))
        # A second IP in the same /24 — distributed infrastructure.
        nb_ip = "203.0.113.46"
        for i in range(6):
            ts = int(base + day * 86400 + 400 + i * 25)
            ani = "1888%07d" % (2220000 + i)
            dni = "3366%04d" % (2000 + i)
            uid = str(_uuid.uuid4())
            ev.append("\t".join([str(ts), ani, dni, nb_ip, uid]))
            dec.append("\t".join([str(ts), ani, dni, nb_ip, "80", "high_risk",
                                  "HIGH_SOURCE_IP_VELOCITY", "0", "0", "NONE", uid]))
        _write(os.path.join(root, "spam_events", d + ".tsv"), "\n".join(ev) + "\n")
        _write(os.path.join(root, "spam_decisions", d + ".tsv"), "\n".join(dec) + "\n")
    # One recorded call that got through analysis with high operational risk.
    d = time.strftime("%Y%m%d", time.localtime(base + 2 * 86400))
    t = "120000"
    ani, dni, uid = "18005550000", "33661000", str(_uuid.uuid4())
    fn = "3366_%s_%s_%s_%s_%s.wav" % (d, t, ani, dni, uid)
    recp = os.path.join(root, "recordings", fn)
    _write(recp, "RIFFsynthetic-wav-placeholder")
    _write(recp[:-4] + ".meta", json.dumps({
        "sig_ip": bad_ip, "media_ip": bad_ip, "sip_code": "200", "connected": True,
        "verstat": "TN-Validation-Failed", "identity_header": "eyJ.x.y"}))
    _write(recp[:-4] + ".analysis", json.dumps({
        "risk_level": "high", "risk_score": 72,
        "red_flags": [{"title": "Impersonation of government agency", "severity": "high"}],
        "summary": "Caller claims to be from a federal agency demanding payment.",
        "azure": {"pii": {"available": True, "count": 2, "categories": {"USSocialSecurityNumber": 1}},
                  "sentiment": {"label": "negative"},
                  "content_safety": {"available": True, "max_severity": 4, "categories": {"Hate": 0, "Violence": 4}}},
        "operational": {"score": 82, "level": "critical", "components": [], "findings": []}}))
    # Reputation overlay.
    _write(os.path.join(root, "spam_reputation_current", "180.tsv"),
           "18005550000\t4\t1\t2026-08-01\n")
    return root


def run_selftest():
    tmp = tempfile.mkdtemp(prefix="voip-intel-selftest-")
    out = os.path.join(tmp, "out")
    os.makedirs(out, exist_ok=True)
    make_synthetic(tmp)
    report = build_report(tmp, since_days=30, min_score=50)
    paths = write_exports(report, out, {"json", "csv", "stix", "blocklist", "dashboard"}, min_score=50)
    s = report["summary"]
    checks = [
        ("indicators found", s["indicators"] >= 2),
        ("critical indicator present", s["critical_indicators"] >= 1),
        ("campaign detected", s["campaigns"] >= 1),
        ("source IP scored critical",
         any(a["value"] == "203.0.113.45" and a["level"] == "critical" for a in report["top_ips"])),
        ("FTC overlay applied",
         any(a["value"] == "18005550000" and a["complaints"] >= 4 for a in report["top_anis"])),
        ("STIX bundle valid",
         _valid_stix(os.path.join(out, "intel.stix.json"))),
        ("sequential-ANI spoofing detected on source IP",
         any(a["value"] == "203.0.113.45" and "SEQUENTIAL-ANI" in a["tags"] for a in report["top_ips"])),
        ("toll-free-origin tag on ANI",
         any("TOLLFREE-ORIGIN" in a["tags"] for a in report["top_anis"])),
        ("bot-cadence detected", any("BOT-CADENCE" in a["tags"]
                                     for a in report["top_ips"] + report["top_anis"])),
        ("spoofing indicators counted", report["summary"]["spoofing_indicators"] >= 1),
        ("subnet /24 correlation", report["summary"]["subnets"] >= 1 and
         any(s["ips"] >= 2 for s in report["subnets"])),
        ("trends non-empty", len(report["trends"]) >= 1),
        ("all exports written", all(os.path.exists(p) for p in paths.values() if isinstance(p, str))),
    ]
    print("voip_intel self-test")
    print("  data dir:", tmp)
    ok = True
    for name, passed in checks:
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
        ok = ok and passed
    print("  summary:", json.dumps(s))
    print("  outputs:", out)
    print("RESULT:", "OK" if ok else "FAILURES")
    return 0 if ok else 1


def _valid_stix(path):
    try:
        b = _read_json(path)
        return b.get("type") == "bundle" and any(o.get("type") == "indicator" for o in b.get("objects", []))
    except Exception:
        return False


# ----------------------------------------------------------------------------
# driver
# ----------------------------------------------------------------------------
def write_exports(report, out_dir, kinds, min_score):
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    if "json" in kinds:
        written["json"] = export_json(report, os.path.join(out_dir, "intel.json"))
    if "csv" in kinds:
        written["csv"] = export_csv(report, os.path.join(out_dir, "indicators.csv"))
    if "stix" in kinds:
        written["stix"] = export_stix(report, os.path.join(out_dir, "intel.stix.json"))
    if "blocklist" in kinds:
        a, i = export_blocklist(report, os.path.join(out_dir, "force_ani.candidates.txt"),
                                os.path.join(out_dir, "force_ip.candidates.txt"), min_score)
        written["blocklist_ani"], written["blocklist_ip"] = a, i
    if "dashboard" in kinds:
        written["dashboard"] = export_dashboard(report, os.path.join(out_dir, "dashboard.html"))
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description="VoIP honeypot threat-intelligence engine")
    ap.add_argument("--data", default="/opt/voip", help="honeypot data root (default /opt/voip)")
    ap.add_argument("--since", type=int, default=30, help="lookback window in days (0 = all)")
    ap.add_argument("--out", default="./intel-out", help="output directory")
    ap.add_argument("--export", default="all",
                    help="comma list: json,csv,stix,blocklist,dashboard,all")
    ap.add_argument("--min-score", type=int, default=50,
                    help="minimum threat score to treat an entity as an indicator")
    ap.add_argument("--selftest", action="store_true", help="run synthetic end-to-end test and exit")
    ap.add_argument("--print-summary", action="store_true", help="print JSON summary to stdout")
    args = ap.parse_args(argv)

    if args.selftest:
        return run_selftest()

    kinds = ({"json", "csv", "stix", "blocklist", "dashboard"}
             if args.export.strip() == "all"
             else {k.strip() for k in args.export.split(",") if k.strip()})
    report = build_report(args.data, args.since, args.min_score)
    written = write_exports(report, args.out, kinds, args.min_score)
    s = report["summary"]
    if args.print_summary:
        print(json.dumps(s, indent=2))
    else:
        print("Analyzed %d attempts / %d recordings over %s days: "
              "%d indicators (%d critical), %d campaigns." % (
                  s["total_attempts"], s["total_recordings"], s["window_days"] or "all",
                  s["indicators"], s["critical_indicators"], s["campaigns"]))
    for label, p in written.items():
        print("  wrote %-14s %s" % (label, p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
