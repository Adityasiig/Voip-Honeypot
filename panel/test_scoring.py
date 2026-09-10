#!/usr/bin/env python3
"""Automated tests for the VoIP operational-risk scoring engine.

Run:  python3 test_scoring.py [path/to/app.py]
Default module path: /opt/voip/app.py  (local dev: pass /tmp/live_app.py)

These tests pin the transparent weighted-sum contract so the 45-vs-28.5 class
of bug can never silently return:
  overall = Σ(component_score × weight) / 100, weights fixed and totalling 100,
  no floors, no multipliers, no double counting, missing data never inflates.
"""
import sys, importlib.util

MODULE_PATH = sys.argv[1] if len(sys.argv) > 1 else "/opt/voip/app.py"
spec = importlib.util.spec_from_file_location("voip_app", MODULE_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

PASS, FAIL = 0, 0
def check(name, cond, got=None, want=None):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}  got={got!r} want={want!r}")

# Canonical component set matching the dashboard weights.
def comps(identity, traffic, content, data, moderation,
          identity_av=True, traffic_av=True, content_av=True, data_av=True, mod_av=True):
    return [
        {"key": "identity",   "weight": app.RISK_WEIGHTS["identity"],   "score": identity,   "available": identity_av},
        {"key": "traffic",    "weight": app.RISK_WEIGHTS["traffic"],    "score": traffic,    "available": traffic_av},
        {"key": "content",    "weight": app.RISK_WEIGHTS["content"],    "score": content,    "available": content_av},
        {"key": "data",       "weight": app.RISK_WEIGHTS["data"],       "score": data,       "available": data_av},
        {"key": "moderation", "weight": app.RISK_WEIGHTS["moderation"], "score": moderation, "available": mod_av},
    ]

print("[weights]")
check("weights total 100", sum(app.RISK_WEIGHTS.values()) == 100, sum(app.RISK_WEIGHTS.values()), 100)

print("[round_half_up]")
check("28.5 rounds to 29", app._round_half_up(28.5) == 29, app._round_half_up(28.5), 29)
check("0.5 rounds to 1",  app._round_half_up(0.5) == 1,  app._round_half_up(0.5), 1)
check("1.4 rounds to 1",  app._round_half_up(1.4) == 1,  app._round_half_up(1.4), 1)

print("[combine_risk_components]")
# The exact case from the bug report: 45 was displayed, correct answer is 29.
score, cov, contribs = app.combine_risk_components(comps(50, 80, 0, 0, 0))
check("bug case = 29 (not 45)", score == 29, score, 29)
check("bug case coverage 100", cov == 100, cov, 100)
check("traffic contribution = 16.0", any(c["key"]=="traffic" and c["contribution"]==16.0 for c in contribs))
check("identity contribution = 12.5", any(c["key"]=="identity" and c["contribution"]==12.5 for c in contribs))
check("sum of contributions ~= 28.5",
      abs(sum(c["contribution"] for c in contribs) - 28.5) < 0.05,
      sum(c["contribution"] for c in contribs), 28.5)

score0, _, _ = app.combine_risk_components(comps(0, 0, 0, 0, 0))
check("all zeros = 0", score0 == 0, score0, 0)

score100, _, _ = app.combine_risk_components(comps(100, 100, 100, 100, 100))
check("all 100s = 100", score100 == 100, score100, 100)

# Missing component must not silently INCREASE risk vs the same component present at 0.
present0, _, _ = app.combine_risk_components(comps(50, 80, 0, 0, 0))
missing,  _, _ = app.combine_risk_components(comps(50, 80, 0, 0, 0, mod_av=False, data_av=False))
check("missing components don't inflate", missing <= present0, missing, f"<= {present0}")
check("missing == present-at-zero (neutral)", missing == present0, missing, present0)

# No double counting: overall never exceeds the max single component when others are 0.
sc, _, _ = app.combine_risk_components(comps(0, 0, 100, 0, 0))
check("single component not double-counted (<=30)", sc == 30, sc, 30)

print("[risk_level thresholds]")
check("0 -> low",       app._risk_level(0) == "low")
check("19 -> low",      app._risk_level(19) == "low")
check("20 -> moderate", app._risk_level(20) == "moderate")
check("44 -> moderate", app._risk_level(44) == "moderate")
check("45 -> high",     app._risk_level(45) == "high")
check("69 -> high",     app._risk_level(69) == "high")
check("70 -> critical", app._risk_level(70) == "critical")

print("[transcript confidence / evidence sufficiency]")
short = app._rule_risk_analysis("Hello. Hi, hello.")
check("short transcript score 0", short["risk_score"] == 0, short["risk_score"], 0)
check("short transcript LOW confidence", short["confidence"] == "low", short["confidence"], "low")
check("short transcript insufficient_evidence", short["evidence_status"] == "insufficient_evidence")
check("short transcript not called 'safe'", "safe" not in short["assessment"].lower(), short["assessment"])
check("short transcript states insufficiency", "insufficient" in short["assessment_reason"].lower())

fraud = app._rule_risk_analysis(
    "Hello sir this is calling from your bank. Your account will be blocked. "
    "Please share the one time password and the OTP now to verify your account immediately.")
check("clear scam scores high", fraud["risk_score"] >= 55, fraud["risk_score"], ">=55")
check("clear scam has red flags", len(fraud["red_flags"]) > 0, len(fraud["red_flags"]))

print("[traffic combined-evidence gate]")
# One lone volume signal from a busy PBX must NOT be marked high on its own.
recs = [{"ani": "1000", "dni": str(9000+i), "sig_ip": "5.5.5.5", "mtime": 1000+i, "size": 200000, "sip_code": "200"}
        for i in range(22)]
tscore, tdetail, tfind, treasons = app._traffic_component(recs[0], recs)
check("22 calls/22 dest/1 IP not critical", tscore < 70, tscore, "<70")
check("traffic reasons are explainable", len(treasons) >= 1, treasons)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
