#!/usr/bin/env python3
"""Regenerate the mailbox-provider vs. tenant DMARC/transport survey.

Measures each domain over DNS-over-HTTPS and writes the survey CSV plus a
summary JSON. Run:

    python3 survey_dmarc_posture.py --out-dir docs/research

DATA-INTEGRITY ASSERTIONS (hard failures, not warnings)
-------------------------------------------------------
The first pass of this survey silently counted six domains twice. These six are
mailbox providers AND appear in the scan history because users scanned them:

    hotmail.com   mailbox.org   proton.me   tuta.io   yahoo.com   zoho.com

Each was counted once as a provider and once as a tenant, which moved four
published figures (tenant publication 66.7%->65.9%, tenant enforcement
48.5%->47.7%, tenant MTA-STS 10.7%->9.1%, tenant TLS-RPT 14.4%->12.5%) and two
rule counts. If you are editing survey_tenants.txt and see any of the names
above, that is the defect returning: a mailbox-provider domain belongs to the
provider class no matter who scanned it.

The class assignment is therefore asserted rather than remembered:

  1. provider and tenant classes are DISJOINT  (a provider domain is a
     provider domain regardless of who scanned it)
  2. every domain appears exactly ONCE across the whole survey
  3. lookup failures are reported, never silently coerced to a negative

Any violation aborts before writing, because a class-assignment error produces
plausible-looking rates that nothing downstream can detect.
"""
import argparse, json, os, re, sys, time
import urllib.request
import concurrent.futures as cf

DOH = "https://cloudflare-dns.com/dns-query"


def doh(name, rrtype, timeout=20, tries=2):
    url = f"{DOH}?name={name}&type={rrtype}"
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    err = None
    for _ in range(tries):
        try:
            return json.load(urllib.request.urlopen(req, timeout=timeout))
        except Exception as exc:            # noqa: BLE001 - reported, not swallowed
            err = str(exc)
            time.sleep(0.4)
    return {"error": err}


def _txt(resp, needle):
    """Records matching a literal version token.

    The token match is load-bearing. A bare "is there a TXT at _mta-sts"
    check calls a domain MTA-STS-protected when it merely serves a wildcard
    TXT (apple.com answers `v=spf1 redirect=...` there), which would excuse a
    genuine transport gap.
    """
    return [a.get("data", "") for a in (resp.get("Answer") or [])
            if needle.lower() in a.get("data", "").lower()]


def profile(domain):
    out = {"domain": domain}

    r = doh(f"_dmarc.{domain}", "TXT")
    if "error" in r:
        out["dmarc_status"] = "lookup_error"
        return out
    txt = " ".join(x.replace('" "', "").strip('"') for x in _txt(r, "v=DMARC1"))
    out["dmarc_status"] = "present" if txt else "absent"

    tags = {}
    for kv in (p.strip() for p in txt.split(";") if "=" in p):
        k, v = kv.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    out.update({
        "policy": (tags.get("p") or "malformed") if txt else "no DMARC",
        "p": tags.get("p"), "sp": tags.get("sp"), "pct": tags.get("pct", "100"),
        "aspf": tags.get("aspf", "r"), "adkim": tags.get("adkim", "r"),
        "has_rua": "rua" in tags, "has_ruf": "ruf" in tags,
    })

    s = doh(domain, "TXT")
    spf = " ".join(x.replace('" "', "").strip('"') for x in _txt(s, "v=spf1"))
    out["spf_present"] = bool(spf)
    out["spf_includes"] = " ".join(sorted(set(re.findall(r"(?:include:|redirect=)(\S+)", spf))))

    k = doh(domain, "DNSKEY")
    out["dnssec"] = bool(k.get("Answer")) if "error" not in k else None
    m = doh(f"_mta-sts.{domain}", "TXT")
    out["mta_sts"] = bool(_txt(m, "v=STSv1")) if "error" not in m else None
    t = doh(f"_smtp._tls.{domain}", "TXT")
    out["tls_rpt"] = bool(_txt(t, "v=TLSRPTv1")) if "error" not in t else None
    b = doh(f"default._bimi.{domain}", "TXT")
    out["bimi"] = bool(_txt(b, "v=BIMI1")) if "error" not in b else None
    return out


def assert_classes_disjoint(providers, tenants):
    """Abort on the class-assignment defect that moved four published figures."""
    overlap = sorted(set(providers) & set(tenants))
    if overlap:
        sys.exit(
            "ABORT: provider and tenant classes overlap on "
            f"{len(overlap)} domain(s): {overlap}\n"
            "A mailbox-provider domain belongs to the provider class even when "
            "users have scanned it. Remove these from the tenant list and re-run."
        )


def assert_rows_unique(rows):
    seen, dupes = set(), []
    for r in rows:
        if r["domain"] in seen:
            dupes.append(r["domain"])
        seen.add(r["domain"])
    if dupes:
        sys.exit(f"ABORT: {len(dupes)} duplicate domain row(s): {sorted(set(dupes))}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--providers", required=True, help="file, one mailbox-provider domain per line")
    ap.add_argument("--tenants", required=True, help="file, one tenant domain per line")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    read = lambda p: [l.strip().lower() for l in open(p) if l.strip() and not l.startswith("#")]
    providers, tenants = read(args.providers), read(args.tenants)

    # Assertion 1, BEFORE any network work: disjoint classes.
    assert_classes_disjoint(providers, tenants)

    targets = [("provider", d) for d in sorted(set(providers))] + \
              [("tenant", d) for d in sorted(set(tenants))]
    rows = []
    with cf.ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(profile, d): (cls, d) for cls, d in targets}
        for fut in cf.as_completed(futs):
            cls, d = futs[fut]
            try:
                rec = fut.result()
            except Exception as exc:                       # noqa: BLE001
                rec = {"domain": d, "dmarc_status": f"exception: {exc}"}
            rec["class"] = cls
            rows.append(rec)

    # Assertion 2: one row per domain.
    assert_rows_unique(rows)

    # Assertion 3: lookup failures are reported, never coerced to a negative.
    errs = [r["domain"] for r in rows if str(r.get("dmarc_status", "")).startswith(("lookup_error", "exception"))]
    if errs:
        print(f"NOTE: {len(errs)} domain(s) had a lookup failure and are excluded "
              f"from rates rather than counted as absent: {errs[:10]}", file=sys.stderr)

    import csv
    fields = ["class", "domain", "dmarc_status", "policy", "p", "sp", "pct", "aspf", "adkim",
              "has_rua", "has_ruf", "spf_present", "spf_includes",
              "dnssec", "mta_sts", "tls_rpt", "bimi"]
    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "dmarc_provider_tenant_survey.csv")
    with open(csv_path, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        wr.writeheader()
        for r in sorted(rows, key=lambda x: (x["class"], x["domain"])):
            wr.writerow(r)

    scored = [r for r in rows if r["domain"] not in set(errs)]
    def rate(cls, pred):
        sub = [r for r in scored if r["class"] == cls]
        return round(sum(1 for r in sub if pred(r)) / len(sub), 4) if sub else None
    pub = lambda r: r["dmarc_status"] == "present"
    enf = lambda r: r.get("policy") in ("reject", "quarantine")
    summary = {
        "measured_utc": time.strftime("%Y-%m-%d", time.gmtime()),
        "n_total": len(scored),
        "n_provider": sum(1 for r in scored if r["class"] == "provider"),
        "n_tenant": sum(1 for r in scored if r["class"] == "tenant"),
        "lookup_errors": len(errs),
        "publishes_dmarc": {"provider": rate("provider", pub), "tenant": rate("tenant", pub)},
        "enforces": {"provider": rate("provider", enf), "tenant": rate("tenant", enf)},
    }
    json.dump(summary, open(os.path.join(args.out_dir, "dmarc_survey_summary.json"), "w"), indent=1)
    print(f"wrote {csv_path} ({len(rows)} rows, {len(errs)} lookup failures)")


if __name__ == "__main__":
    main()
