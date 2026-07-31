// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// GENERATED — do not hand-edit. Regenerate with scripts/refresh-ud-tlds.sh
//
// Unstoppable Domains TLDs that are NOT ICANN TLDs, derived by subtraction:
//
//	web3 set = UD catalogue  MINUS  IANA root zone
//
//	UD catalogue  https://api.unstoppabledomains.com/resolve/supported_tlds   356
//	IANA root     https://data.iana.org/TLD/tlds-alpha-by-domain.txt        1438
//	intersection (ICANN TLDs UD also sells)                                  207
//	difference  = this list                                                  149
//
// Fetched 2026-07-31.
//
// Why IANA and not UD's own `ud_tld_list`: that endpoint returns the 203
// ICANN TLDs UD SELLS as a registrar, which is a sales inventory, not the
// ICANN root. Subtracting it leaves 153 entries — 4 of them genuine ICANN
// TLDs UD simply does not sell — |catalogue ∩ IANA| is 207 while ud_tld_list
// is 203 — which would then be misclassified as Web3 names and skip the DNS
// battery they legitimately need. (Those four are not named: identifying them
// needs ud_tld_list, an MCP endpoint unreachable from this checkout, so the
// count is arithmetic and the membership unverified.) IANA publishes the root zone, so it is the
// producer for "is this an ICANN TLD"; the vendor list answers a different
// question. (`ud_tld_list` also returns ZERO Web3 TLDs, so it cannot be the
// producer for this list in either direction.)
//
// `com` and the rest of the ICANN overlap are removed BY CONSTRUCTION — they
// appear in both inputs, so the subtraction drops them. There is no
// hand-maintained exclusion list, because a remembered list only ever
// excludes what someone remembered.
// dns-tool:scrutiny science
package analyzer

// udWeb3TLDs is the generated set. Membership means: Unstoppable Domains
// resolves this TLD on-chain and ICANN does not delegate it, so a name under
// it has no DNS zone and must not be scored as though it did.
var udWeb3TLDs = map[string]bool{
	"888":           true,
	"agent":         true,
	"ai4":           true,
	"altimist":      true,
	"amped":         true,
	"anime":         true,
	"anyone":        true,
	"arculus":       true,
	"ask":           true,
	"ath":           true,
	"aura":          true,
	"austin":        true,
	"awaken":        true,
	"bald":          true,
	"basenji":       true,
	"bay":           true,
	"bch":           true,
	"benji":         true,
	"binanceus":     true,
	"bitcoin":       true,
	"bitget":        true,
	"bitscrunch":    true,
	"blockchain":    true,
	"bobi":          true,
	"boomer":        true,
	"brave":         true,
	"bunni":         true,
	"calicoin":      true,
	"carbon":        true,
	"cashme":        true,
	"caw":           true,
	"cgai":          true,
	"chip":          true,
	"chipper":       true,
	"chomp":         true,
	"clay":          true,
	"coin":          true,
	"collect":       true,
	"crypto":        true,
	"dao":           true,
	"dejay":         true,
	"demos":         true,
	"depin":         true,
	"derad":         true,
	"dfz":           true,
	"digibyte":      true,
	"digitalfuture": true,
	"doga":          true,
	"donut":         true,
	"dream":         true,
	"dsci":          true,
	"emir":          true,
	"enigma":        true,
	"eth":           true,
	"ethermail":     true,
	"farms":         true,
	"go":            true,
	"goblin":        true,
	"gotchi":        true,
	"grow":          true,
	"hegecoin":      true,
	"her":           true,
	"hi":            true,
	"horizen":       true,
	"housecoin":     true,
	"hub":           true,
	"imtoken":       true,
	"kingdom":       true,
	"klever":        true,
	"kresus":        true,
	"kryptic":       true,
	"learn":         true,
	"lfg":           true,
	"ltc":           true,
	"lunar":         true,
	"manga":         true,
	"marketer":      true,
	"mery":          true,
	"metropolis":    true,
	"miku":          true,
	"ministry":      true,
	"mobix":         true,
	"moon":          true,
	"mooncat":       true,
	"mumu":          true,
	"mycircle":      true,
	"nft":           true,
	"nibi":          true,
	"npc":           true,
	"og":            true,
	"ohm":           true,
	"onchain":       true,
	"openx":         true,
	"pack":          true,
	"pastor":        true,
	"pbdx":          true,
	"pendle":        true,
	"pengu":         true,
	"pilot":         true,
	"podcast":       true,
	"pog":           true,
	"pokt":          true,
	"polygon":       true,
	"presearch":     true,
	"privacy":       true,
	"propykeys":     true,
	"pudgy":         true,
	"pundi":         true,
	"quantum":       true,
	"rad":           true,
	"raiin":         true,
	"realm":         true,
	"retardio":      true,
	"secret":        true,
	"smobler":       true,
	"sonic":         true,
	"south":         true,
	"spend":         true,
	"stepn":         true,
	"super":         true,
	"supernova":     true,
	"swamp":         true,
	"tball":         true,
	"tea":           true,
	"tigershark":    true,
	"tribe":         true,
	"troll":         true,
	"twin":          true,
	"u":             true,
	"ubu":           true,
	"udtest":        true,
	"undeads":       true,
	"unstoppable":   true,
	"vanity":        true,
	"verge":         true,
	"wallet":        true,
	"web3":          true,
	"wif":           true,
	"wifi":          true,
	"witg":          true,
	"wrkx":          true,
	"x":             true,
	"xec":           true,
	"xmr":           true,
	"xyo":           true,
	"xz1":           true,
	"yellow":        true,
	"zano":          true,
	"zil":           true,
}
