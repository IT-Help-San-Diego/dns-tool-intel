import json
import glob
import os

# --- INPUT DISCOVERY (server-safe, no Downloads dependency) ---
files = glob.glob("Inputs/dns-intelligence-*.json")
if not files:
    raise FileNotFoundError("Place DNS JSON into Inputs/ before running.")

# Select newest file by modification time
SOURCE = max(files, key=os.path.getmtime)
DEST = "Mappings/normalized-from-dnstool.json"

with open(SOURCE, "r") as f:
    raw = json.load(f)

fr = raw.get("full_results", {})
domain = raw.get("domain", "unknown")

dnssec = fr.get("dnssec_analysis", {})
smtp = fr.get("smtp_transport", {})
spf = fr.get("spf_analysis", {})
dmarc = fr.get("dmarc_analysis", {})
mail = fr.get("mail_posture", {})
tlsrpt = fr.get("tlsrpt_analysis", {})
mta_sts = fr.get("mta_sts_analysis", {})
caa = fr.get("caa_analysis", {})

normalized = {
    "source_file": os.path.basename(SOURCE),
    "domain": domain,
    "observations": {
        "DNSSEC_VALID": dnssec.get("status") == "success" and dnssec.get("ad_flag") is True,
        "DNSSEC_INHERITED": dnssec.get("chain_of_trust") == "inherited",
        "NULL_MX": fr.get("has_null_mx", False),
        "SPF_HARD_FAIL": spf.get("all_mechanism") == "-all",
        "DMARC_REJECT": dmarc.get("policy") == "reject",
        "NO_MAIL_DOMAIN": mail.get("verdict") == "no_mail",
        "TLS_RPT": tlsrpt.get("status") == "success",
        "MTA_STS_DNS": mta_sts.get("status") in ("success", "warning"),
        "CAA_PRESENT": caa.get("status") == "success" and bool(caa.get("records"))
    }
}

with open(DEST, "w") as f:
    json.dump(normalized, f, indent=2)

print(json.dumps(normalized, indent=2))
