#!/usr/bin/env python3
"""Assemble the Engineer's Report workspace from the canonical report source.

results.html remains the content authority. This generator relocates every
source line exactly once into a navigable disclosure gradient; it never edits
or abbreviates protocol evidence. The output is an independently-rendered
candidate at /analysis/:id/v2 until the information architecture is ratified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "templates" / "results.html"
DST = ROOT / "templates" / "results_v2.html"
SOURCE_LINE_COUNT = 7106

lines = SRC.read_text().split("\n")
assert len(lines) >= SOURCE_LINE_COUNT, (
    f"results.html has {len(lines)} lines; map expects {SOURCE_LINE_COUNT} — REMAP FIRST"
)


def seg(a: int, b: int) -> str:
    """Return a one-indexed inclusive line range from the canonical template."""

    return "\n".join(lines[a - 1 : b])


@dataclass(frozen=True)
class Group:
    anchor: str
    title: str
    number: str
    eyebrow: str
    question: str
    level: str
    open_by_default: bool
    ranges: tuple[tuple[int, int], ...]
    chips: tuple[tuple[str, str], ...]


GROUPS = (
    Group(
        "email-security",
        "Email Security",
        "01",
        "Identity & policy",
        "Can this domain be impersonated by email?",
        "L1",
        True,
        ((960, 2016),),
        (
            ("SPF", "section-email"),
            ("DMARC", "section-email"),
            ("DKIM", "section-email"),
            ("MTA-STS", "section-email"),
            ("TLS-RPT", "section-email"),
            ("MX & Routing", "section-traffic"),
        ),
    ),
    Group(
        "domain-security",
        "Domain Security",
        "02",
        "Chain of authority",
        "Can DNS answers and certificate issuance be trusted?",
        "L1",
        False,
        ((2381, 2565), (2702, 2756), (3690, 3840), (3961, 4100), (4720, 5184)),
        (
            ("DANE / TLSA", "section-dane"),
            ("CAA", "section-caa"),
            ("Delegation", "section-delegation-consistency"),
            ("DNSSEC Operations", "section-dnssec-ops"),
            ("DNSSEC & NS", "section-dnssec"),
        ),
    ),
    Group(
        "transport-security",
        "Transport Security",
        "03",
        "Delivery path",
        "Will mail transport resist downgrade and interception?",
        "L1",
        False,
        ((4198, 4568),),
        (("STARTTLS", "section-smtp"), ("MTA-STS policy", "section-smtp"), ("TLS-RPT", "section-smtp")),
    ),
    Group(
        "brand-trust",
        "Brand & Trust",
        "04",
        "Human-visible identity",
        "Can this brand be convincingly faked?",
        "L1",
        False,
        ((2566, 2701), (2757, 2823)),
        (("BIMI & VMC", "section-brand"), ("CAA · see Domain Security", "section-caa")),
    ),
    Group(
        "infrastructure-intel",
        "Infrastructure Intelligence",
        "05",
        "Ownership & attack surface",
        "Who operates this domain, and what is exposed?",
        "L1",
        False,
        (
            (2824, 2953),
            (2954, 3053),
            (3054, 3219),
            (3220, 3500),
            (3501, 3600),
            (3601, 3689),
            (3841, 3960),
            (4101, 4197),
            (4569, 4719),
            (5185, 5337),
            (5338, 5747),
            (5748, 5786),
        ),
        (
            ("Registrar / RDAP", "section-infra"),
            ("security.txt", "section-securitytxt"),
            ("Web Exposure", "section-web-exposure"),
            ("AI Surface", "section-ai"),
            ("Web3", "section-web3"),
            ("Subdomains", "section-subdomains"),
        ),
    ),
    Group(
        "evidence-verification",
        "Evidence & Verification",
        "06",
        "Raw records & reproducibility",
        "Can another engineer reproduce every material claim?",
        "L2–L3",
        False,
        (
            (2017, 2058),
            (2059, 2289),
            (2290, 2344),
            (2345, 2380),
            (5787, 6325),
        ),
        (
            ("Analysis Confidence", "confidencePanel"),
            ("Intelligence Currency", "currencyPanel"),
            ("What changed", "section-dns-diff"),
            ("Raw record diff", "section-dns-diff"),
            ("Integrity seal", "report-integrity"),
            ("Reproduce", "verify-commands"),
        ),
    ),
)

# Coverage proof: every canonical source line appears exactly once. Generated
# workspace chrome is additive and therefore excluded from source coverage.
covered: list[tuple[int, int]] = [(1, 959), (6326, SOURCE_LINE_COUNT)]
for group in GROUPS:
    covered.extend(group.ranges)
seen = [0] * (SOURCE_LINE_COUNT + 1)
for start, end in covered:
    for line_number in range(start, end + 1):
        seen[line_number] += 1
bad = [number for number in range(1, SOURCE_LINE_COUNT + 1) if seen[number] != 1]
assert not bad, f"coverage failure at lines {bad[:12]} (each source line must appear exactly once)"

# Give the relocated CAA card its ratified canonical anchor. The replacement is
# scoped to the CAA column wrapper and asserted once; source bytes remain intact.
CAA_COLUMN = '<div class="{{if .IsPublicSuffix}}col-12{{else}}col-md-6{{end}}">'


CSS = r'''
<!-- Engineer workspace — generated by report-mint/assemble_v2.py -->
<style nonce="{{.CspNonce}}">
  :root {
    --er-bg: #0a0f16;
    --er-layer-1: #111925;
    --er-layer-2: #172231;
    --er-layer-3: #1d2b3c;
    --er-line: rgba(142, 165, 189, .24);
    --er-line-strong: rgba(142, 165, 189, .42);
    --er-gold: #d4a853;
    --er-gold-soft: #e8c77f;
    --er-blue: #78a9d4;
    --er-green: #56d364;
    --er-text: #e6edf3;
    --er-muted: #aeb9c5;
    --er-radius: 10px;
  }
  html { scroll-padding-top: 8.5rem; }
  body { background: var(--er-bg); }
  #main-content.v2-workspace { max-width: 1440px; }
  .v2-workspace .results-header {
    position: relative; display: grid; grid-template-columns: minmax(20rem, 1fr) minmax(28rem, auto);
    gap: 1.25rem; padding: 1.25rem; margin-bottom: 1rem !important;
    background: linear-gradient(135deg, rgba(23,34,49,.98), rgba(10,15,22,.98));
    border: 1px solid var(--er-line); border-top: 3px solid var(--er-gold); border-radius: var(--er-radius);
  }
  .v2-workspace .results-header-info h1 { color: var(--er-muted); font-size: .78rem; font-weight: 600; letter-spacing: .14em; text-transform: uppercase; }
  .v2-workspace .domain-name-prominent { color: var(--er-text); font-size: clamp(1.85rem, 4vw, 3.1rem); font-weight: 400; letter-spacing: -.035em; line-height: 1.05; }
  .v2-workspace .results-meta { color: var(--er-muted) !important; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .73rem !important; margin-top: .7rem; }
  .v2-workspace .results-header-actions { align-content: flex-start; justify-content: flex-end; }
  .v2-workspace .results-header-actions .btn { min-height: 40px; }
  .v2-workspace .results-header-actions .dropdown { display: none; }
  .v2-orientation {
    display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(18rem, .65fr); gap: 1px;
    margin: 1rem 0; border: 1px solid var(--er-line); border-radius: var(--er-radius); overflow: hidden;
    background: var(--er-line);
  }
  .v2-orientation > div { background: var(--er-layer-1); padding: 1rem 1.15rem; }
  .v2-kicker, .v2-level, .v2-summary-eyebrow {
    color: var(--er-gold-soft); font-size: .68rem; font-weight: 700; letter-spacing: .13em; text-transform: uppercase;
  }
  .v2-orientation h2 { margin: .3rem 0 .4rem; color: var(--er-text); font-size: 1.15rem; font-weight: 500; }
  .v2-orientation p { margin: 0; color: var(--er-muted); font-size: .86rem; line-height: 1.55; }
  .v2-layer-key { display: grid; grid-template-columns: repeat(4, 1fr); gap: .45rem; margin-top: .75rem; }
  .v2-layer-key span { padding-top: .45rem; border-top: 2px solid var(--er-line-strong); color: var(--er-muted); font-size: .7rem; }
  .v2-layer-key strong { display: block; color: var(--er-text); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .v2-hurry { display: grid; gap: .55rem; }
  .v2-hurry a { display: flex; align-items: center; justify-content: space-between; min-height: 42px; padding: .55rem .75rem; color: var(--er-text); text-decoration: none; background: var(--er-layer-2); border-left: 3px solid var(--er-gold); }
  .v2-hurry a:hover, .v2-hurry a:focus-visible { background: var(--er-layer-3); color: #fff; }
  .v2-nav {
    position: sticky; top: 0; z-index: 1030; display: grid; grid-template-columns: repeat(6, minmax(9rem, 1fr));
    gap: 1px; margin: 1rem 0; padding: 1px; background: rgba(10,15,22,.96); border: 1px solid var(--er-line);
    box-shadow: 0 10px 32px rgba(0,0,0,.38); backdrop-filter: blur(18px);
  }
  .v2-nav a { display: grid; grid-template-columns: auto 1fr; gap: .55rem; align-items: center; min-height: 52px; padding: .55rem .7rem; color: var(--er-muted); text-decoration: none; background: var(--er-layer-1); }
  .v2-nav a:hover, .v2-nav a:focus-visible, .v2-nav a[aria-current="location"] { color: var(--er-text); background: var(--er-layer-3); box-shadow: inset 0 -2px var(--er-gold); }
  .v2-nav-index { color: var(--er-gold-soft); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .72rem; }
  .v2-nav-label { font-size: .76rem; font-weight: 600; line-height: 1.25; }
  .v2-groups { display: grid; gap: .75rem; }
  details.v2-group { scroll-margin-top: 8rem; border: 1px solid var(--er-line); border-radius: var(--er-radius); overflow: clip; background: var(--er-layer-1); }
  details.v2-group > summary { cursor: pointer; list-style: none; display: grid; grid-template-columns: 3.2rem minmax(13rem, .7fr) minmax(18rem, 1.3fr) auto; gap: 1rem; align-items: center; min-height: 92px; padding: .85rem 1rem; }
  details.v2-group > summary::-webkit-details-marker { display: none; }
  details.v2-group > summary:hover { background: var(--er-layer-2); }
  details.v2-group[open] > summary { background: var(--er-layer-2); border-bottom: 1px solid var(--er-line); }
  .v2-summary-index { color: var(--er-gold-soft); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1.15rem; }
  .v2-summary-title { display: block; color: var(--er-text); font-size: 1.12rem; font-weight: 600; }
  .v2-summary-question { display: block; margin-top: .25rem; color: var(--er-muted); font-size: .78rem; font-weight: 400; line-height: 1.35; }
  .v2-toc { display: flex; flex-wrap: wrap; gap: .35rem; }
  .v2-toc-chip { display: inline-flex; align-items: center; min-height: 30px; padding: .22rem .55rem; color: var(--er-muted); text-decoration: none; font-size: .7rem; font-weight: 500; background: rgba(10,15,22,.45); border: 1px solid var(--er-line); border-radius: 999px; }
  .v2-toc-chip:hover, .v2-toc-chip:focus-visible { color: var(--er-text); border-color: var(--er-gold); }
  .v2-summary-toggle { color: var(--er-muted); transition: transform .18s ease; }
  details[open] .v2-summary-toggle { transform: rotate(180deg); }
  .v2-group-body { padding: 1rem; background: var(--er-bg); }
  .v2-group-body > .row, .v2-group-body > .card, .v2-group-body > .tech-footprint-strip { scroll-margin-top: 8.5rem; }
  .v2-group-body .card { border-color: var(--er-line); box-shadow: none; }
  .v2-group-body .card-header { border-bottom-color: var(--er-line); }
  .v2-workspace #command-card { margin-bottom: .75rem !important; }
  .v2-workspace #command-card > .col-12 > .card { border-width: 1px !important; border-left-width: 4px !important; }
  .v2-workspace #command-card .card-body { padding: 1rem !important; }
  .v2-workspace #findings-summary, .v2-workspace #findings-summary + .row { margin-bottom: .75rem !important; }
  .v2-workspace .domain-summary-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .v2-workspace .domain-summary-row > [class*="col-"] { width: auto; max-width: none; padding: .75rem 1rem; margin: 0 !important; }
  .v2-workspace .tech-footprint-strip { border-radius: var(--er-radius); }
  /* Bird's-eye posture verdicts: compact strip instead of a tall 4-up stack. */
  .v2-workspace .v2-posture-strip { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem 1.15rem; text-align: left; }
  .v2-workspace .v2-posture-strip > [class*="col-"] { width: auto; max-width: none; flex: none; padding: 0 !important; margin: 0 !important; display: inline-flex; align-items: center; gap: .5rem; }
  .v2-workspace .v2-posture-strip .small { margin: 0 !important; font-size: .68rem !important; letter-spacing: .05em; }
  .v2-workspace .v2-posture-strip .badge { padding: .28rem .6rem !important; font-size: .72rem !important; }
  /* Priority-action DNS record tables: let long values wrap instead of squinting mid-token. */
  .v2-workspace .table-dark td code { overflow-wrap: anywhere; word-break: break-word; white-space: normal; }
  .v2-workspace .u-col-label-70 { width: 3.4rem; }
  .v2-edge { display: inline-flex; margin-left: .5rem; padding: .15rem .45rem; color: var(--er-blue); border: 1px solid rgba(120,169,212,.35); border-radius: 999px; font-size: .68rem; text-decoration: none; }
  [data-v2-level="L0"] { --v2-level-color: var(--er-gold); }
  [data-v2-level="L1"] { --v2-level-color: var(--er-blue); }
  [data-v2-level="L2"], [data-v2-level="L3"] { --v2-level-color: var(--er-green); }
  details.v2-group { border-left: 3px solid var(--v2-level-color, var(--er-line-strong)); }
  @media (max-width: 1199px) {
    .v2-workspace .results-header { grid-template-columns: 1fr; }
    .v2-workspace .results-header-actions { justify-content: flex-start; }
    .v2-nav { grid-template-columns: repeat(3, 1fr); }
    details.v2-group > summary { grid-template-columns: 2.5rem 1fr auto; }
    .v2-toc { grid-column: 2 / -1; }
  }
  @media (max-width: 767px) {
    #main-content.v2-workspace { margin-top: 1rem !important; }
    .v2-orientation { grid-template-columns: 1fr; }
    .v2-layer-key { grid-template-columns: repeat(2, 1fr); }
    .v2-nav { grid-template-columns: repeat(2, 1fr); position: relative; }
    .v2-nav a { min-height: 48px; }
    details.v2-group > summary { grid-template-columns: 2rem 1fr auto; gap: .55rem; min-height: 76px; }
    .v2-toc { grid-column: 1 / -1; }
    .v2-group-body { padding: .65rem; }
    .v2-workspace .domain-summary-row { grid-template-columns: 1fr 1fr; }
  }
  @media (prefers-reduced-motion: reduce) { .v2-summary-toggle { transition: none; } }
  @media print {
    .v2-orientation, .v2-nav, .v2-summary-toggle, .screen-only { display: none !important; }
    details.v2-group { border: 0; }
    details.v2-group > summary { display: block; }
    details.v2-group:not([open]) > *:not(summary) { display: block !important; }
    .v2-workspace .v2-group-body, .v2-workspace .card, .v2-workspace .results-header { break-inside: avoid; page-break-inside: avoid; }
    .v2-workspace .table-dark td code { overflow-wrap: anywhere; }
  }
</style>
'''

ORIENTATION = r'''
<section class="v2-orientation screen-only" aria-label="Report orientation" data-v2-level="L0">
  <div>
    <span class="v2-kicker">Engineer workspace · evidence preserved</span>
    <h2>Read the verdict first. Descend only as far as the incident requires.</h2>
    <p>This report keeps the complete technical record while separating decision, interpretation, evidence, and raw reproduction into a stable disclosure gradient.</p>
    <div class="v2-layer-key" aria-label="Disclosure gradient">
      <span><strong>L0</strong>Posture</span><span><strong>L1</strong>Interpretation</span><span><strong>L2</strong>Evidence</span><span><strong>L3</strong>Raw & reproduce</span>
    </div>
  </div>
  <div>
    <span class="v2-kicker">Hurry path</span>
    <div class="v2-hurry">
      <a href="#section-traffic"><span>MX &amp; Routing</span><span aria-hidden="true">→</span></a>
      <a href="#section-subdomains"><span>Subdomains</span><span aria-hidden="true">→</span></a>
      <a href="#section-dnssec"><span>DNSSEC</span><span aria-hidden="true">→</span></a>
      <a href="#section-dns-diff"><span>What changed</span><span aria-hidden="true">→</span></a>
    </div>
  </div>
</section>
'''

SCRIPT = r'''
<script nonce="{{.CspNonce}}">
(function(){
  function openFor(el){ for(var d=el; d; d=d.parentElement){ if(d.tagName==='DETAILS') d.open=true; } }
  function goHash(){ var id=decodeURIComponent(location.hash.slice(1)); if(!id) return;
    var t=document.getElementById(id); if(t){ openFor(t); t.scrollIntoView({block:'start'}); }
  }
  function updateCurrent(){
    var current=''; var y=globalThis.scrollY+180;
    for(var g of document.querySelectorAll('details.v2-group[id]')){ if(g.offsetTop<=y) current=g.id; }
    for(var a of document.querySelectorAll('.v2-nav a')){
      if(a.getAttribute('href')==='#'+current) a.setAttribute('aria-current','location');
      else a.removeAttribute('aria-current');
    }
  }
  window.addEventListener('hashchange', goHash);
  window.addEventListener('scroll', updateCurrent, {passive:true});
  if(location.hash) setTimeout(goHash,0);
  setTimeout(updateCurrent,0);
  window.addEventListener('beforeprint',function(){ for(var d of document.querySelectorAll('details')){ d.setAttribute('data-was-open', d.open); d.open=true; } });
  window.addEventListener('afterprint',function(){ for(var d of document.querySelectorAll('details')){ if(d.getAttribute('data-was-open')==='false') d.open=false; } });
  document.addEventListener('click',function(e){
    var a=e.target&&e.target.closest?e.target.closest('a[href^="#"]'):null; if(!a)return;
    var t=document.getElementById(decodeURIComponent(a.getAttribute('href').slice(1))); if(!t)return;
    openFor(t);
    if(a.closest('summary')){
      e.preventDefault(); e.stopPropagation();
      if('#'+t.id===location.hash){t.scrollIntoView({block:'start'});}else{location.hash=t.id;}
    }
  },true);
})();
</script>
'''


def chip_row(chips: tuple[tuple[str, str], ...], *, edge: bool = False) -> str:
    links = []
    for label, anchor in chips:
        attr = ' data-edge="see-also"' if edge and anchor == "section-caa" else ""
        links.append(f'<a class="v2-toc-chip"{attr} href="#{anchor}">{label}</a>')
    return '<span class="v2-toc">' + " ".join(links) + "</span>"


def group_markup(group: Group) -> str:
    parts = [
        f'<details class="v2-group" id="{group.anchor}" data-v2-level="{group.level}"' + (" open" if group.open_by_default else "") + ">",
        "<summary>",
        f'<span class="v2-summary-index">{group.number}</span>',
        '<span class="v2-summary-copy">',
        f'<span class="v2-summary-eyebrow">{group.eyebrow} · {group.level}</span>',
        f'<span class="v2-summary-title">{group.title}</span>',
        f'<span class="v2-summary-question">{group.question}</span>',
        "</span>",
        chip_row(group.chips, edge=group.anchor == "brand-trust"),
        '<span class="v2-summary-toggle" aria-hidden="true">⌄</span>',
        "</summary>",
        '<div class="v2-group-body">',
    ]
    content = "\n".join(seg(start, end) for start, end in group.ranges)
    if group.anchor == "domain-security":
        assert content.count(CAA_COLUMN) == 1, "CAA wrapper changed — remap canonical card"
        content = content.replace(CAA_COLUMN, CAA_COLUMN[:-1] + ' id="section-caa">', 1)
    parts.extend((content, "</div>", "</details>"))
    return "\n".join(parts)


NAV = '<nav class="v2-nav screen-only" aria-label="Engineer report workspace">\n' + "\n".join(
    f'  <a href="#{group.anchor}"><span class="v2-nav-index">{group.number}</span><span class="v2-nav-label">{group.title}</span></a>'
    for group in GROUPS
) + "\n</nav>"

# Frame the report immediately after the subject header. The old L0 stack still
# renders below, but the workspace/navigation now owns the first decision frame.
out = [seg(1, 355), CSS, ORIENTATION, NAV, SCRIPT, seg(356, 959), '<div class="v2-groups">']
out.extend(group_markup(group) for group in GROUPS)
out.extend(("</div>", seg(6326, SOURCE_LINE_COUNT)))
html = "\n".join(out)
html = html.replace('<main id="main-content" class="container my-4"', '<main id="main-content" class="container my-4 v2-workspace"', 1)
html = html.replace("<title>", "<title>[ENGINEER WORKSPACE] ", 1)
html = html.replace('<div class="row g-3 text-center">', '<div class="row g-3 text-center v2-posture-strip">', 1)
# The source template contains a few whitespace-only lines; normalize generated
# output so repository gates fail only on semantic drift, not template spacing.
html = "\n".join(line.rstrip() for line in html.splitlines()) + "\n"

# Output-level invariants: these catch generator mistakes before Go sees the file.
for group in GROUPS:
    assert html.count(f'id="{group.anchor}"') == 1, f"duplicate or missing group {group.anchor}"
assert "V2 STRUCTURAL PREVIEW" not in html
assert "Ungrouped — pending contract" not in html
assert html.count('id="section-caa"') == 1

DST.write_text(html)
print(f"WROTE {DST}: {len(html.splitlines())} lines from {len(lines)} canonical source lines")
