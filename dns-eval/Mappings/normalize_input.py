"""
normalize_input.py -- tri-state normalizer for the ICSAE harness (schema v9).

Reads a DNS Tool dns-intelligence-*.json scan and emits observations with a
THREE-STATE contract:

    true  -> measured, condition holds
    false -> measured, condition does NOT hold
    null  -> NOT measured (section absent, status n/a/error/info, ambiguous)

A missing or indeterminate measurement is NEVER equivalent to false.
evaluate.py grades null as not_measured: excluded from the denominator.

Semantics are grounded in the producer's real vocabulary:
  dnssec: status success|warning|n/a ; chain_of_trust complete|inherited|none|broken|...
  spf/dmarc: status success|missing|n/a ; all_mechanism ; policy
  mail: top-level is_no_mail_domain, mail_posture.verdict ('no_mail' is real),
        mail_posture.is_no_mail
  mta_sts: mode enforce|testing ; status 'warning' = "No MTA-STS record found"
           (measured ABSENCE -> false, never present)
  tlsrpt: status success ; 'warning' = "No TLS-RPT record found" -> false
  caa: status success + records ; 'warning' = no CAA records -> false

Usage:
  python3 normalize_input.py [SOURCE.json] [DEST.json]
  No args: discover Inputs/dns-intelligence-*.json, take newest by mtime.
  If the newest file is unparseable, FAIL LOUDLY (never silently grade a
  different domain). Explicit paths always for reproducible runs.
"""
import json
import glob
import os
import sys

if len(sys.argv) >= 2:
    SOURCE = sys.argv[1]
else:
    files = sorted(glob.glob("Inputs/dns-intelligence-*.json"))
    if not files:
        raise FileNotFoundError("Place DNS JSON into Inputs/ before running.")
    SOURCE = max(files, key=os.path.getmtime)

DEST = sys.argv[2] if len(sys.argv) >= 3 else "Mappings/normalized-from-dnstool.json"

try:
    with open(SOURCE, "r") as f:
        raw = json.load(f)
except (json.JSONDecodeError, UnicodeDecodeError) as e:
    raise SystemExit(f"FATAL: {SOURCE} is not parseable JSON ({e}). "
                     f"Refusing to grade a different domain; fix or pass an explicit path.")

fr = raw.get("full_results", {})
domain = raw.get("domain", "unknown")

dnssec = fr.get("dnssec_analysis", {})
spf = fr.get("spf_analysis", {})
dmarc = fr.get("dmarc_analysis", {})
mail = fr.get("mail_posture", {})
tlsrpt = fr.get("tlsrpt_analysis", {})
mta_sts = fr.get("mta_sts_analysis", {})
caa = fr.get("caa_analysis", {})
dkim = fr.get("dkim_analysis", {})
dane = fr.get("dane_analysis", {})
bimi = fr.get("bimi_analysis", {})
security_txt = fr.get("security_txt", {})
dangling = fr.get("dangling_dns", {})
delegation = fr.get("delegation_consistency", {})
secret_exp = fr.get("secret_exposure", {})
https_svcb = fr.get("https_svcb", {})
cds_cdnskey = fr.get("cds_cdnskey", {})
calibrated = fr.get("calibrated_confidence", {})

ns_delegation = fr.get("ns_delegation_analysis", {})
is_subdomain = ns_delegation.get("is_subdomain", False)

ns_fleet_data = fr.get("ns_fleet", {})
ns_names = [ns.get("name", "") for ns in ns_fleet_data.get("nameservers", [])] if isinstance(ns_fleet_data.get("nameservers"), list) else []
provider_hint = "route53" if any("awsdns" in n for n in ns_names) else "cloudflare" if any("cloudflare" in n for n in ns_names) else "other"

# --- tri-state signal helpers ---
def tri_str(value):
    """measured string -> the string itself; else None"""
    return value if isinstance(value, str) and value else None

# DNSSEC: chain is the semantic field; ad is the resolver flag.
chain = tri_str(dnssec.get("chain_of_trust"))
dnssec_status = tri_str(dnssec.get("status"))
if chain in ("complete", "inherited") and dnssec_status == "success" and dnssec.get("ad_flag") is True:
    dnss_valid = True
elif chain in ("none", "broken"):
    dnss_valid = False
else:
    dnss_valid = None
dnss_chain_valid = dnss_valid  # same semantics per the v8 registry

# DNSSEC rollover readiness
rollover = None
if any(k in cds_cdnskey for k in ("has_cds", "has_cdnskey", "automation")):
    rollover = bool(cds_cdnskey.get("has_cds") or cds_cdnskey.get("has_cdnskey")
                    or cds_cdnskey.get("automation") == "active")

# NULL MX
null_mx = fr.get("has_null_mx") if "has_null_mx" in fr else None

# SPF
spf_mech = tri_str(spf.get("all_mechanism"))
if spf_mech is not None:
    spf_hard = (spf_mech == "-all")
    spf_soft = (spf_mech == "~all")
elif spf.get("status") == "missing":
    spf_hard, spf_soft = False, False
else:
    spf_hard, spf_soft = None, None

# DMARC
dmarc_pol = tri_str(dmarc.get("policy"))
if dmarc_pol is not None:
    dmarc_reject = (dmarc_pol == "reject")
    dmarc_enforcing = dmarc_pol in ("reject", "quarantine")
elif dmarc.get("status") == "missing":
    dmarc_reject, dmarc_enforcing = False, False
else:
    dmarc_reject, dmarc_enforcing = None, None

if spf_soft is False:
    spf_softfail_dmarc = False
elif spf_soft is True and dmarc_enforcing is True:
    spf_softfail_dmarc = True
elif spf_soft is True and dmarc_enforcing is False:
    spf_softfail_dmarc = False
else:
    spf_softfail_dmarc = None

# no-mail / mail domain: any true signal -> true; any measured signal, none true -> false
_signals = [fr.get("is_no_mail_domain"),
            (mail.get("verdict") == "no_mail") if "verdict" in mail else None,
            mail.get("is_no_mail")]
_measured = [s for s in _signals if s is not None]
if any(s is True for s in _signals):
    no_mail = True
elif _measured:
    no_mail = False
else:
    no_mail = None
mail_domain = (not no_mail) if no_mail is not None else None

def tri_status(section, true_states=("success",), false_states=("warning",)):
    st = section.get("status")
    if st in true_states:
        return True
    if st in false_states:
        return False
    return None

tls_rpt = tri_status(tlsrpt)
mta = True if mta_sts.get("mode") in ("enforce", "testing") else tri_status(mta_sts)
caa_st = caa.get("status")
if caa_st == "success" and caa.get("records"):
    caa_present = True
elif caa_st == "warning":
    caa_present = False
else:
    caa_present = None

if isinstance(dkim.get("primary_has_dkim"), bool):
    dkim_found = dkim.get("primary_has_dkim")
elif dkim.get("status") in ("missing",):
    dkim_found = False
else:
    dkim_found = None

dane_present = dane.get("has_dane") if isinstance(dane.get("has_dane"), bool) else None

if bimi.get("status") == "success":
    bimi_valid = bimi.get("logo_valid") is True
elif bimi.get("status") in ("warning", "missing"):
    bimi_valid = False
else:
    bimi_valid = None

if isinstance(security_txt.get("found"), bool):
    sec_txt = security_txt.get("found") and not security_txt.get("expired", False)
elif security_txt.get("status") in ("missing", "warning"):
    sec_txt = False
else:
    sec_txt = None

if dangling.get("status") == "success" and isinstance(dangling.get("dangling_count"), int):
    no_dangling = dangling.get("dangling_count") == 0
elif dangling.get("status") in ("warning",):
    no_dangling = False
else:
    no_dangling = None

if delegation.get("status") == "success":
    delegation_ok = True
elif delegation.get("status") in ("warning", "failure"):
    delegation_ok = False
else:
    delegation_ok = None

if secret_exp.get("status") == "clear" and isinstance(secret_exp.get("finding_count"), int):
    no_secrets = secret_exp.get("finding_count") == 0
elif secret_exp.get("status") in ("found", "warning"):
    no_secrets = False
else:
    no_secrets = None

if any(k in https_svcb for k in ("has_https", "has_svcb")):
    svcb = bool(https_svcb.get("has_https") or https_svcb.get("has_svcb"))
elif https_svcb.get("status") in ("absent", "warning", "missing"):
    svcb = False
else:
    svcb = None

normalized = {
    "source_file": os.path.basename(SOURCE),
    "domain": domain,
    "is_mail_domain": mail_domain,
    "is_no_mail_domain": no_mail,
    "is_subdomain": is_subdomain,
    "dns_provider_hint": provider_hint,
    "calibrated_confidence": calibrated,
    "state_model": "tri-state (true|false|null); null = not measured, never a control failure",
    "observations": {
        "DNSSEC_VALID": dnss_valid,
        "DNSSEC_CHAIN_VALID": dnss_chain_valid,
        "DNSSEC_ROLLOVER_READY": rollover,
        "NULL_MX": null_mx,
        "SPF_HARD_FAIL": spf_hard,
        "SPF_SOFTFAIL_WITH_DMARC": spf_softfail_dmarc,
        "DMARC_REJECT": dmarc_reject,
        "DMARC_ENFORCING": dmarc_enforcing,
        "NO_MAIL_DOMAIN": no_mail,
        "MAIL_DOMAIN": mail_domain,
        "TLS_RPT": tls_rpt,
        "MTA_STS_DNS": mta,
        "CAA_PRESENT": caa_present,
        "DKIM_FOUND": dkim_found,
        "DANE_PRESENT": dane_present,
        "BIMI_VALID": bimi_valid,
        "SECURITY_TXT_FOUND": sec_txt,
        "NO_DANGLING_DNS": no_dangling,
        "DELEGATION_OK": delegation_ok,
        "NO_SECRETS_EXPOSED": no_secrets,
        "HTTPS_SVCB_PRESENT": svcb,
    },
    "context": {
        "dnssec_chain_type": chain or "",
        "spf_mechanism": spf_mech or "",
        "dmarc_policy": dmarc_pol or "",
        "spf_dmarc_effective": "enforced" if (spf_hard or (spf_soft and dmarc_enforcing)) else "unenforced"
    }
}

with open(DEST, "w") as f:
    json.dump(normalized, f, indent=2)

print(json.dumps(normalized, indent=2))
