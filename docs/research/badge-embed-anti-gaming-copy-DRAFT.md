# /badge/embed — anti-gaming copy (DRAFT for Hermes's badgepkg PR)

Drafted 2026-08-02 by Claude Code per Science's vocabulary ruling + Hermes's
structural verification (badge.go line cites in the card). Hand-off: fold these
sections into badge_embed.html in the badgepkg PR — do not ship separately, the
copy and the code fixes (Gateway-Derived adjacency, tri-state labels, compact
date) assert each other. Tone-matched to the site's measurement-first voice;
Carey arbitrates wording.

---

## Section: Beta disclosure (TOP OF PAGE — Carey 2026-08-02: "still beta, missing from the top")

**BETA** — The badge program is in beta (as declared on the validation table,
approach.html). What may change while it is: the vocabulary, the rendering, and
the embed formats. What will not change: the discipline — a badge only ever
describes a stored public measurement, and it will never say `Safe`. If you
embed a beta badge, expect its look to evolve; its honesty is the stable API.

Suggested rendering: the existing `validation-status-beta` chip style from
approach.html, placed beside the page title — same visual language, one
convention.

## Section: What a badge is

**A badge is a measurement, not a compliment.**

Every DNS Tool badge describes what the public instrument measured about your
zone — declared policy, measured from a single vantage point across three
independent public resolvers (Quad9, Cloudflare, Google) at one instant, and
recorded with its resolver agreement. Single vantage is a stated limitation,
not a footnote: split-horizon DNS, GeoDNS, and regional anycast can make your
local view legitimately differ from the instrument's — which is why the badge
tells you how it measured, so you can dispute it on the level it actually
operates. (Multi-vantage probing is roadmap, and this sentence changes when it
ships — not before.)
`Hardened` means your published records met the strongest posture the
measurement can establish. It does not mean "safe." No badge we issue says
`Safe`, `Secure`, or `Verified`, because the instrument cannot measure those
claims: it can see that DMARC is at `p=reject`; it cannot see whether your keys
leaked, whether anyone is spoofing you right now, or what your zone will say
tomorrow. A badge that claimed more than the measurement would be decoration.
Ours are readings.

## Section: Why you can't game it (and why we won't help)

**We don't generate badges from what you tell us.**

A badge renders only from a stored measurement row in the public database,
keyed to its analysis id, carrying its measurement timestamp. There is no
parameter that makes a badge say something the instrument didn't measure — not
for you, not for your robot, not for ours. If your zone's posture is `Exposed`,
the badge says `Exposed` until a new public measurement says otherwise. The fix
for a bad badge is fixing your zone, and the instrument will happily confirm it
the moment you have.

Every badge shows **when** it was measured. A green badge with an old date is
an old reading, and says so on its face — re-scan and it updates. A badge that
hid its age would be the gaming surface; ours wears it.

## Section: Local is sovereign — and unbadgeable

**Badges read only the public database. That's not a policy; it's the
construction.**

Scans you keep local never leave your machine, so there is nothing public for
a badge to read — sovereignty and unbadgeability are the same property.
Publishing a scan (the publish toggle, default off, labeled with exactly what
leaves your machine) is what creates the public measurement a badge can point
at. Private analyses are excluded from badge rendering outright.

> **SHIP GATE (verified 2026-08-02, do not remove until the PR lands):** the
> paragraph above is true for `private` today (handler checks at
> badge.go:129/:144) but NOT yet query-level, and `scan_flag` /
> `analysis_success` are checked NOWHERE on the badge path — a flagged or
> failed row can currently badge. Also the domain path takes newest-row-then-
> check, so a newest-private scan hides an older PUBLIC one ("not scanned"
> instead of badging the newest public measurement). This copy ships ONLY with
> Hermes's badgepkg PR item 4: dedicated badge queries carrying
> `AND private = FALSE AND scan_flag = FALSE AND analysis_success = TRUE`,
> which fixes the layer, the gaps, and the newest-public semantics at once.

---

### Vocabulary note (for the page footer or tooltip, Science's ruling)

`Hardened` · `Partial` · `Exposed` · `Wide Open` · `Critical Risk` describe
measured configuration posture. Provenance (how the measurement was obtained)
renders **beside** the posture, never in its place. "Measured but
indeterminate" and "no measurement exists" are different facts and carry
different labels — a reader can always tell a failed check from an absent one.
