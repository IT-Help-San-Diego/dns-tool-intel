#!/usr/bin/env python3
"""Assemble results_v2.html from results.html by verified section ranges.

Structural preview of the report IA contract: the five contract groups become
progressive-disclosure shells in contract order; sections the contract doesn't
yet home go to a labeled 'ungrouped' tail in original order; everything else
(head, L0 dashboard, evidence/verify tail, scripts) keeps its original text.
Line ranges come from the 2026-08-02 recon map of results.html@f90b5f82f —
re-run the recon before re-running this against a moved file.
"""
import sys

SRC = '../../templates/results.html'
DST = '../../templates/results_v2.html'

lines = open(SRC).read().split('\n')
assert len(lines) >= 7340, f"results.html has {len(lines)} lines; map expects 7340 — REMAP FIRST"

def seg(a, b):  # 1-indexed inclusive
    return '\n'.join(lines[a-1:b])

GROUPS = [
    ('email-security', 'Email Security', True, [(1037, 2223)]),
    ('domain-security', 'Domain Security', False, [(2588, 2772), (3897, 4047), (4156, 4295), (4915, 5379)]),
    ('transport-security', 'Transport Security', False, [(4393, 4763)]),
    ('brand-trust', 'Brand & Trust', False, [(2773, 3030)]),
    ('infrastructure-intel', 'Infrastructure Intelligence', False, [(4048, 4155), (4764, 4914), (5380, 5532), (5533, 5942)]),
]
TAIL = [(2224, 2265), (2266, 2496), (2497, 2551), (2552, 2587), (3031, 3160),
        (3161, 3260), (3261, 3426), (3427, 3707), (3708, 3807), (3808, 3896),
        (4296, 4392), (5943, 5981)]

# Coverage proof: every line 1..7340 exactly once.
covered = []
covered.append((1, 1036))
for _, _, _, ranges in GROUPS: covered += ranges
covered += TAIL
covered.append((5982, 7340))
seen = [0] * (7340 + 1)
for a, b in covered:
    for i in range(a, b + 1): seen[i] += 1
bad = [i for i in range(1, 7341) if seen[i] != 1]
assert not bad, f"coverage failure at lines {bad[:10]} (each must appear exactly once)"

STYLE = '''
<!-- ============ V2 STRUCTURAL PREVIEW (report IA contract) ============ -->
<style nonce="{{.CspNonce}}">
  .v2-banner { border: 2px dashed #b45309; color: #b45309; font-weight: 700;
               padding: .5rem .75rem; margin: .75rem 0; border-radius: 4px; }
  .v2-nav { position: sticky; top: 0; z-index: 1030; display: flex; gap: .4rem;
            flex-wrap: wrap; padding: .5rem .25rem; margin: .75rem 0;
            background: var(--bg-primary, #111); border-bottom: 1px solid var(--border-default, #444); }
  .v2-nav a { font-size: .78rem; padding: .2rem .6rem; border: 1px solid var(--border-default, #555);
              border-radius: 999px; text-decoration: none; white-space: nowrap; }
  details.v2-group { border: 1px solid var(--border-default, #444); border-radius: 6px;
                     margin: 1rem 0; }
  details.v2-group > summary { cursor: pointer; padding: .6rem .9rem; font-weight: 700;
                     font-size: 1.05rem; list-style: revert; }
  details.v2-group > summary .v2-anchor { color: #9ca3af; font-size: .7rem;
                     font-family: ui-monospace, monospace; font-weight: 400; }
  .v2-group-body { padding: 0 .9rem .9rem; }
  details.v2-group[open] > summary { border-bottom: 1px solid var(--border-default, #333); }
</style>
<div class="v2-banner screen-only">V2 STRUCTURAL PREVIEW — contract IA (groups + disclosure + nav); zero visual design;
all content relocated, none removed. Judge structure against /analysis/&lt;id&gt; (v1). Sections not yet homed by the
contract sit under "Ungrouped" in original order.</div>
<nav class="v2-nav screen-only" aria-label="Report sections">
  <a href="#email-security">Email Security</a>
  <a href="#domain-security">Domain Security</a>
  <a href="#transport-security">Transport Security</a>
  <a href="#brand-trust">Brand &amp; Trust</a>
  <a href="#infrastructure-intel">Infrastructure Intelligence</a>
  <a href="#v2-ungrouped">Ungrouped</a>
  <a href="#dns-evidence">Evidence &amp; History</a>
  <a href="#findings-summary">Findings</a>
</nav>
'''

out = []
out.append(seg(1, 1036))
out.append(STYLE)
for anchor, title, is_open, ranges in GROUPS:
    openattr = ' open' if is_open else ''
    out.append(f'<details class="v2-group" id="{anchor}"{openattr}>')
    out.append(f'<summary>{title} <span class="v2-anchor">#{anchor}</span></summary>')
    out.append('<div class="v2-group-body">')
    for a, b in ranges:
        out.append(seg(a, b))
    out.append('</div>\n</details>')
out.append('<details class="v2-group" id="v2-ungrouped">')
out.append('<summary>Ungrouped — pending contract v1.1 group homes <span class="v2-anchor">#v2-ungrouped</span></summary>')
out.append('<div class="v2-group-body">')
for a, b in TAIL:
    out.append(seg(a, b))
out.append('</div>\n</details>')
out.append('<div id="dns-evidence"></div>')
out.append(seg(5982, 7340))

html = '\n'.join(out)
# v2 page identity: keep noindex; canonical/og stay pointed at the v1 URL (unchanged text does that already).
html = html.replace('<title>', '<title>[V2 PREVIEW] ', 1)
open(DST, 'w').write(html)
print(f"WROTE {DST}: {len(html.splitlines())} lines from {len(lines)} source lines")
