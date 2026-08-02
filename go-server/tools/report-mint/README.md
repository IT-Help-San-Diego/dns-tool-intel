# report-mint — skeleton (engine + contract proof)

Step 2 of the report-redesign sequence (blessed 2026-08-02): prove the mint
engine and the page furniture against `docs/design/REPORT-IA-CONTRACT.md` v0,
**before any visual design**. The design lane owns everything aesthetic; this
tool exists so the contract's mechanisms are demonstrated on real data
(analysis 47, google.com) and the engine choice is de-risked offline — no
server route, no production Chromium dependency until the deploy lane signs
off on one.

## Run

```
npm install
node mint.js out.pdf
```

Chromium resolution: `$MINT_CHROMIUM` → Playwright headless shell → Chrome.
On the dev Mac, full Chrome hangs headless under managed policies; the
Playwright headless shell (`chromium_headless_shell-1194`) is the working
binary.

## What each contract section proves out here

| Contract | Where in the skeleton |
|---|---|
| §1 anchors | chip/card `id` attributes; the `#mta-sts` string is identical on the p.1 chip and the p.2 appendix heading |
| §2 canonical + typed edges | one card per protocol; p.2 shows a `see-also` (no status) and the BIMI `requires → dmarc` with inline target status |
| §3 status vocabulary | status **words** on every chip (redundant to color); `draft-spec` marker on BIMI |
| §4 gradient in print | document order L0 → L1/L2 samples → L3 appendix; commands relocated, never dropped |
| §5 scale rule | 819 subdomains: count stated, bound stated, pointer to full set |
| §6 citations | DMARC card carries RFC 7489 §6.3 with a normative-language fragment (sentence selection = Science's open item) |
| §7 provenance + sentinels | `app_version` is `''` on row 47 and renders **"not recorded"**; resolver/vantage honestly absent; mint time distinct from measurement time; epistemic-mark slot renders its pending state loudly |
| Running furniture | Chromium header/footer templates (CSS margin-boxes are unsupported in Chromium print) — provenance line + page numbers on every page |

The `SKELETON MINT` watermark and banner are contract-load-bearing: this
artifact must never circulate as a real report.
