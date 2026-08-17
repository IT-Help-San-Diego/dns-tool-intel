"""
evaluate.py -- tri-state grader for the ICSAE harness (schema v9).

Grades normalized observations against the ISO 27001/27002 + INCITS control
mappings with a THREE-STATE contract (see normalize_input.py):

    true  = measured, holds
    false = measured, does not hold
    null  = not measured

Verdicts:
    passed          every required observation measured and true
                    (requires_any: at least one required true)
    failed          a required observation measured false
                    (requires_any: all required measured false)
    not_measured    required observation(s) null and no measured false
                    -> EXCLUDED from the denominator, never a failure
    not_applicable  applies_when gate measured false
                    (applies_when with a null observation -> not_measured)

Usage:
  python3 evaluate.py [OBSERVATIONS.json] [OUT.json]
  Defaults: Mappings/normalized-from-dnstool.json -> Mappings/evaluation-results.json
  Explicit paths for reproducible runs.
"""
import json
import sys
from datetime import datetime, timezone

OBS_PATH = sys.argv[1] if len(sys.argv) >= 2 else "Mappings/normalized-from-dnstool.json"
OUT_PATH = sys.argv[2] if len(sys.argv) >= 3 else "Mappings/evaluation-results.json"

with open("Mappings/dns-to-controls.json") as f:
    registry = json.load(f)

mappings = registry["mappings"]
standards_reg = registry.get("standards_registry", {})
rfc_reg = registry.get("rfc_registry", {})

with open(OBS_PATH) as f:
    data = json.load(f)

obs = data["observations"]
confidence = data.get("calibrated_confidence", {})
context = data.get("context", {})
provider_hint = data.get("dns_provider_hint", "unknown")
is_subdomain = data.get("is_subdomain", False)

ICIE_SOURCE_TIERS = {
    "DNSSEC": {"tier": 1, "label": "Authoritative DNS", "note": "Tier 1 — cryptographic validation from authoritative zone"},
    "SPF": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — RFC-defined TXT record semantics"},
    "DMARC": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — RFC-defined TXT record semantics"},
    "DKIM": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — RFC-defined TXT record semantics"},
    "CAA": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — RFC-defined resource record semantics"},
    "DANE": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — DNSSEC-dependent TLSA records"},
    "BIMI": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — TXT record with logo binding"},
    "MTA_STS": {"tier": 8, "label": "Web Intelligence", "note": "Tier 8 — HTTPS-fetched policy, transient"},
    "TLS_RPT": {"tier": 2, "label": "Protocol Records", "note": "Tier 2 — RFC-defined TXT record"},
    "DELEGATION": {"tier": 1, "label": "Authoritative DNS", "note": "Tier 1 — parent/child NS delegation"},
    "SECRET": {"tier": 8, "label": "Web Intelligence", "note": "Tier 8 — HTTP page source scan"},
    "SECURITY_TXT": {"tier": 8, "label": "Web Intelligence", "note": "Tier 8 — .well-known HTTPS fetch"}
}

results = []

for m in mappings:
    applies = m.get("applies_when", [])
    if applies:
        vals = [obs.get(k) for k in applies]
        if any(v is False for v in vals):
            results.append({
                "id": m["id"], "title": m.get("title", m["id"]),
                "status": "not_applicable", "severity": m["severity"],
                "standards": m.get("standards", []), "rfcs": m.get("rfcs", []),
                "rationale": m.get("rationale", ""), "fail_explanation": ""})
            continue
        if any(v is None for v in vals):
            results.append({
                "id": m["id"], "title": m.get("title", m["id"]),
                "status": "not_measured", "severity": m["severity"],
                "standards": m.get("standards", []), "rfcs": m.get("rfcs", []),
                "rationale": m.get("rationale", ""), "fail_explanation": ""})
            continue

    if "requires" in m:
        req = m["requires"]
        vals = [obs.get(k) for k in req]
        if any(v is False for v in vals):
            passed = "failed"
        elif all(v is True for v in vals):
            passed = "passed"
        else:
            passed = "not_measured"
    elif "requires_any" in m:
        req = m["requires_any"]
        vals = [obs.get(k) for k in req]
        if any(v is True for v in vals):
            passed = "passed"
        elif all(v is False for v in vals):
            passed = "failed"
        else:
            passed = "not_measured"
    else:
        passed = "not_measured"

    results.append({
        "id": m["id"], "title": m.get("title", m["id"]),
        "status": passed, "severity": m["severity"],
        "standards": m.get("standards", []), "rfcs": m.get("rfcs", []),
        "rationale": m.get("rationale", ""),
        "fail_explanation": m.get("fail_explanation", "") if passed == "failed" else ""})

failed = [r for r in results if r["status"] == "failed"]
passed_l = [r for r in results if r["status"] == "passed"]
na = [r for r in results if r["status"] == "not_applicable"]
not_measured = [r for r in results if r["status"] == "not_measured"]
null_obs = sorted(k for k, v in obs.items() if v is None)

summary = {
    "domain": data["domain"],
    "source": data["source_file"],
    "evaluated_at": datetime.now(timezone.utc).isoformat(),
    "schema_version": registry.get("schema_version"),
    "total_controls": len(results),
    "passed_count": len(passed_l),
    "failed_count": len(failed),
    "na_count": len(na),
    "not_measured_count": len(not_measured),
    "measured_controls": len(failed) + len(passed_l),
    "null_observations": null_obs,
    "high_failures": [r["id"] for r in failed if r["severity"] == "high"],
    "medium_failures": [r["id"] for r in failed if r["severity"] == "medium"],
    "low_failures": [r["id"] for r in failed if r["severity"] == "low"],
    "passed": [r["id"] for r in passed_l],
    "not_applicable": [r["id"] for r in na],
    "not_measured": [r["id"] for r in not_measured],
    "results": results
}

with open(OUT_PATH, "w") as f:
    json.dump(summary, f, indent=2)


def format_citation(ref_id):
    if ref_id.startswith("RFC"):
        rfc = rfc_reg.get(ref_id, {})
        if rfc:
            authors = ", ".join(rfc.get("authors", []))
            return f'{authors}, "{rfc["title"]}," {ref_id} ({rfc.get("status", "")}, {rfc.get("date", "")}). {rfc.get("url", "")}'
        return ref_id
    parts = ref_id.split(":")
    std_key = parts[0]
    clause = parts[1] if len(parts) > 1 else None
    std = standards_reg.get(std_key, {})
    if std:
        cite = f'{std.get("identifier", std_key)}, "{std["title"]}," {std.get("publisher", "")} ({std.get("date", "")})'
        if clause:
            cite += f", §{clause}"
        return cite + "."
    return ref_id


W = 72
SEP = "=" * W
THIN = "-" * W

print(SEP)
print("ICSAE — Intelligence Compliance & Standards Assessment Engine")
print(SEP)
print(f"  Domain:     {data['domain']}")
print(f"  Source:      {data['source_file']}")
print(f"  Provider:    {provider_hint}")
if is_subdomain:
    print(f"  Type:        Subdomain (inheritance rules apply per RFC 8659)")
print(f"  Evaluated:   {summary['evaluated_at']}")
print(f"  Controls:    {summary['total_controls']} evaluated, {summary['passed_count']} passed, "
      f"{summary['failed_count']} failed, {summary['not_measured_count']} not measured, {summary['na_count']} N/A")
print(f"  Denominator: {summary['measured_controls']} measured (not_measured excluded — never a failure)")
if null_obs:
    print(f"  Unmeasured:  {', '.join(null_obs)}")
if context.get("spf_dmarc_effective"):
    spf_mech = context.get("spf_mechanism", "?")
    dmarc_pol = context.get("dmarc_policy", "?")
    eff = context["spf_dmarc_effective"]
    print(f"  Mail Auth:   SPF {spf_mech} + DMARC p={dmarc_pol} → {eff}")
print(SEP)

if not failed and not passed_l:
    print("\n  STATUS: NOTHING MEASURED")
    print("  No observation was measurable — no verdict is claimed.\n")
elif not failed:
    print("\n  STATUS: ALL MEASURED CONTROLS PASSED")
    if not_measured:
        print(f"  ({len(not_measured)} control(s) not measured — excluded from the denominator)\n")
    else:
        print("  Strong standards-aligned security posture.\n")
else:
    print(f"\n  STATUS: {len(failed)} CONTROL(S) REQUIRE ATTENTION\n")

for severity_label in ["HIGH", "MEDIUM", "LOW"]:
    sev_results = [r for r in failed if r["severity"] == severity_label.lower()]
    if not sev_results:
        continue
    print(f"\n{'':>2}[{severity_label} PRIORITY]")
    print(THIN)
    for r in sev_results:
        print(f"\n  {'✗':>2} {r['title']}")
        print(f"     Control: {r['id']}")
        if r["fail_explanation"]:
            lines = r["fail_explanation"]
            print(f"\n     FINDING:")
            for line in lines.split(". "):
                line = line.strip()
                if line:
                    if not line.endswith("."):
                        line += "."
                    print(f"       {line}")
        if r["standards"]:
            print(f"\n     STANDARDS:")
            for s in r["standards"]:
                print(f"       → {format_citation(s)}")
        if r["rfcs"]:
            print(f"\n     RFCs:")
            for rfc_id in r["rfcs"]:
                print(f"       → {format_citation(rfc_id)}")
        conf_keys = {
            "DNSSEC": "DNSSEC", "SPF": "SPF", "DMARC": "DMARC",
            "DKIM": "DKIM", "DANE": "DANE", "CAA": "CAA",
            "BIMI": "BIMI", "MTA_STS": "MTA_STS", "TLS_RPT": "TLS_RPT"
        }
        relevant_conf = []
        relevant_tiers = []
        for ck, cv in conf_keys.items():
            if ck.lower() in r["id"].lower():
                if cv in confidence:
                    relevant_conf.append((cv, confidence[cv]))
                if ck in ICIE_SOURCE_TIERS:
                    relevant_tiers.append((ck, ICIE_SOURCE_TIERS[ck]))
        for k in ["DELEGATION", "SECRET", "SECURITY_TXT"]:
            if k.lower() in r["id"].lower() and k in ICIE_SOURCE_TIERS:
                relevant_tiers.append((k, ICIE_SOURCE_TIERS[k]))
        if relevant_conf or relevant_tiers:
            print(f"\n     INTELLIGENCE PROVENANCE:")
            for name, val in relevant_conf:
                print(f"       ICD 203 Confidence ({name}): {val}")
            for name, tier in relevant_tiers:
                print(f"       ICIE Source Authority: {tier['note']}")
        print()

if passed_l:
    print(f"\n{'':>2}[PASSED CONTROLS]")
    print(THIN)
    for r in passed_l:
        print(f"  {'✓':>2} {r['title']} ({r['id']})")
        if "DNSSEC_CHAIN" in r["id"] and context.get("dnssec_chain_type"):
            chain_t = context["dnssec_chain_type"]
            if chain_t == "inherited" and is_subdomain:
                print(f"       ℹ Chain type: inherited from parent zone (valid for subdomains)")
            elif chain_t == "complete":
                print(f"       ℹ Chain type: complete (zone has own DS/DNSKEY)")
        if "SPF" in r["id"] and obs.get("SPF_SOFTFAIL_WITH_DMARC"):
            print(f"       ℹ SPF ~all + DMARC p={context.get('dmarc_policy','reject')} = operationally enforced")
        if r["standards"]:
            for s in r["standards"]:
                print(f"       → {format_citation(s)}")
        if r["rfcs"]:
            for rfc_id in r["rfcs"][:2]:
                print(f"       → {format_citation(rfc_id)}")
        print()

if not_measured:
    print(f"\n{'':>2}[NOT MEASURED — EXCLUDED FROM DENOMINATOR]")
    print(THIN)
    for r in not_measured:
        print(f"  {'○':>2} {r['title']} ({r['id']})")
    print()

if na:
    print(f"\n{'':>2}[NOT APPLICABLE]")
    print(THIN)
    for r in na:
        print(f"  {'—':>2} {r['title']} ({r['id']})")
    print()

print(SEP)
print("BIBLIOGRAPHY")
print(SEP)

cited_rfcs = set()
cited_stds = set()
for r in results:
    for rfc_id in r.get("rfcs", []):
        cited_rfcs.add(rfc_id)
    for std_ref in r.get("standards", []):
        std_key = std_ref.split(":")[0]
        cited_stds.add(std_key)

print("\n  Standards:\n")
for sk in sorted(cited_stds):
    std = standards_reg.get(sk, {})
    if std:
        ident = std.get("identifier", sk)
        print(f"  [{ident}]")
        print(f"    {std['title']}.")
        print(f"    {std.get('publisher', '')} ({std.get('date', '')}).")
        if std.get("url"):
            print(f"    {std['url']}")
        print()

print("  RFCs:\n")
for rfc_id in sorted(cited_rfcs, key=lambda x: int(x.replace("RFC", ""))):
    rfc = rfc_reg.get(rfc_id, {})
    if rfc:
        authors = ", ".join(rfc.get("authors", []))
        print(f"  [{rfc_id}]")
        print(f"    {authors}.")
        print(f'    "{rfc["title"]}."')
        print(f"    {rfc.get('status', '')} ({rfc.get('date', '')}).")
        print(f"    {rfc.get('url', '')}")
        print()

print(SEP)
