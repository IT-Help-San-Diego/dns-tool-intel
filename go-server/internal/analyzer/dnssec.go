// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/dnsclient"
)

const (
        mapKeyAdFlag               = "ad_flag"
        mapKeyAdResolver           = "ad_resolver"
        mapKeyAdConsensus          = "ad_consensus"
        mapKeyResolverAD           = "resolver_ad"
        mapKeyAlgorithm            = "algorithm"
        mapKeyAlgorithmName        = "algorithm_name"
        mapKeyAlgorithmObservation = "algorithm_observation"
        mapKeyChainOfTrust         = "chain_of_trust"
        mapKeyDnskeyRecords        = "dnskey_records"
        mapKeyDsRecords            = "ds_records"
        mapKeyHasDnskey            = "has_dnskey"
        mapKeyHasDs                = "has_ds"
        mapKeyDnssecState          = "dnssec_state"
        mapKeyUnmeasuredReason     = "unmeasured_reason"
        mapKeyDisplayLabel         = "display_label"
        mapKeyDisplaySeverity      = "display_severity"

        // DNSSEC tri-state, mirroring DANE. dnssec_state lets drift tell a
        // genuine "unsigned zone" apart from a probe that failed transiently, so
        // a timed-out DNSKEY/DS lookup never reads as "DNSSEC removed".
        dnssecStatePresent       = "present"
        dnssecStateAbsentConf    = "absent_confirmed"
        dnssecStateIndeterminate = "indeterminate"
        // dnssecStatePartial = the zone is signed (DNSKEY present) but the parent's
        // authoritative servers confirm there is NO DS — a genuine broken chain /
        // island of security (RFC 6781 §4.2.2). It is NOT "present" (the chain to the
        // parent is incomplete) and NOT "absent_confirmed" (the zone IS signed). This
        // state is only ever set AFTER an authoritative parent confirmation, so it can
        // never be a fabricated "DS missing" verdict derived from a consensus miss.
        dnssecStatePartial = "partial"
        // dnssecStateUnmeasured = the parent scan deadline expired before DNSSEC
        // could be measured. Distinct from "indeterminate" ("we measured and the
        // protocol cannot say"): this is "we never got to measure" and belongs on
        // the unmeasured counter, never merged into honest-uncertainty.
        dnssecStateUnmeasured = "unmeasured"
)

// dnssecDisplayLabel maps the honest dnssec_state + chain_of_trust to a single
// user-facing label + severity, so every template renders the SAME honest
// verdict from one source — never re-deriving "Signed/Unsigned" from the raw
// status string, which is what produced the "signed zone reads Unsigned" bug.
// A zone whose DNSKEY+DS are present but whose validation is broken/unconfirmed/
// unmeasured must never be labeled "Unsigned": it IS signed; the honest label is
// Broken / Unconfirmed / Could Not Verify.
func dnssecDisplayLabel(state, chain string) (label, severity string) {
        switch state {
        case dnssecStateAbsentConf:
                return "Unsigned", "warning"
        case dnssecStatePartial:
                return "Partially Signed", "warning"
        case dnssecStateIndeterminate:
                return "Could Not Verify", "secondary"
        case dnssecStateUnmeasured:
                return "Not Measured", "secondary"
        case dnssecStatePresent:
                switch chain {
                case "complete":
                        return "Signed", "success"
                case "broken":
                        return "Broken", "danger"
                case "unconfirmed":
                        return "Unconfirmed", "warning"
                case "unknown":
                        return "Could Not Verify", "secondary"
                case "inherited":
                        return "Inherited", "success"
                }
        }
        return "Unsigned", "warning"
}

// RebucketDNSSECDisplayLabel backfills display_label + display_severity on a
// persisted dnssec_analysis map written before those fields existed, so old
// rows render the same honest label as a fresh scan (single source of truth —
// never re-derived per-template). Idempotent: a map that already carries the
// fields is left untouched.
func RebucketDNSSECDisplayLabel(results map[string]any) {
        dnssec, _ := results["dnssec_analysis"].(map[string]any)
        if dnssec == nil {
                return
        }
        if _, ok := dnssec[mapKeyDisplayLabel]; ok {
                return
        }
        state, _ := dnssec[mapKeyDnssecState].(string)
        chain, _ := dnssec[mapKeyChainOfTrust].(string)
        label, severity := dnssecDisplayLabel(state, chain)
        dnssec[mapKeyDisplayLabel] = label
        dnssec[mapKeyDisplaySeverity] = severity
}

var algorithmNames = map[int]string{
        1: "RSAMD5", 3: "DSA", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
        7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 10: "RSA/SHA-512",
        12: "ECC-GOST", 13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
        15: "Ed25519", 16: "Ed448",
}

func parseAlgorithm(dsRecords []string) (*int, *string) {
        if len(dsRecords) == 0 {
                return nil, nil
        }
        parts := strings.Fields(dsRecords[0])
        if len(parts) < 2 {
                return nil, nil
        }
        algNum, err := strconv.Atoi(parts[1])
        if err != nil {
                return nil, nil
        }
        algorithm := &algNum
        if name, ok := algorithmNames[algNum]; ok {
                return algorithm, &name
        }
        n := fmt.Sprintf("Algorithm %d", algNum)
        return algorithm, &n
}

type dnssecParams struct {
        hasDNSKEY     bool
        hasDS         bool
        adState       string
        resolverAD    map[string]string
        dnskeyRecords []string
        dsRecords     []string
        algorithm     *int
        algorithmName *string
        adResolver    *string
}

func algorithmObservation(algo *int) map[string]any {
        if algo == nil {
                return nil
        }
        c := ClassifyDNSSECAlgorithm(*algo)
        return map[string]any{
                "strength":     c.Strength,
                "label":        c.Label,
                "rfc":          c.RFC,
                "observation":  c.Observation,
                "quantum_note": c.QuantumNote,
        }
}

func buildDNSSECResult(p dnssecParams) map[string]any {
        if p.hasDNSKEY && p.hasDS {
                var message string
                status := "success"
                chain := "complete"
                switch p.adState {
                case "secure":
                        message = "DNSSEC fully configured and validated — AD (Authenticated Data) flag set by validating resolvers confirming cryptographic chain of trust from root to zone (RFC 4035 §3.2.3)"
                case "bogus":
                        message = "DNSSEC configured (DNSKEY + DS records present) but validation failed — the chain of trust is broken (RFC 4033 §5: bogus is signaled via SERVFAIL / RCODE=2)."
                        status = "warning"
                        chain = "broken"
                case "split":
                        message = "DNSSEC configured (DNSKEY + DS records present) but validating resolvers disagree on the chain — not uniformly confirmed."
                        status = "warning"
                        chain = "unconfirmed"
                case "unmeasured":
                        message = "DNSSEC configured (DNSKEY + DS records present) but the AD flag could not be measured — all validating resolvers were unreachable."
                        status = statusUnknown
                        chain = statusUnknown
                default: // ad_absent
                        message = "DNSSEC configured (DNSKEY + DS records present) but the chain of trust is unconfirmed — the AD flag was absent, and RFC 4033 §5 notes the signaling mechanism cannot distinguish Insecure from Indeterminate."
                        status = "warning"
                        chain = "unconfirmed"
                }
                label, severity := dnssecDisplayLabel(dnssecStatePresent, chain)
                return map[string]any{
                        mapKeyStatus:               status,
                        mapKeyMessage:              message,
                        mapKeyHasDnskey:            true,
                        mapKeyHasDs:                true,
                        mapKeyDnskeyRecords:        p.dnskeyRecords,
                        mapKeyDsRecords:            p.dsRecords,
                        mapKeyAlgorithm:            derefInt(p.algorithm),
                        mapKeyAlgorithmName:        derefStr(p.algorithmName),
                        mapKeyAlgorithmObservation: algorithmObservation(p.algorithm),
                        mapKeyChainOfTrust:         chain,
                        mapKeyAdFlag:               p.adState == "secure",
                        mapKeyAdConsensus:          p.adState,
                        mapKeyResolverAD:           p.resolverAD,
                        mapKeyAdResolver:           derefStr(p.adResolver),
                        mapKeyDnssecState:          dnssecStatePresent,
                        mapKeyDisplayLabel:         label,
                        mapKeyDisplaySeverity:      severity,
                }
        }

        if p.hasDNSKEY && !p.hasDS {
                label, severity := dnssecDisplayLabel(dnssecStatePartial, "broken")
                return map[string]any{
                        mapKeyStatus:               "warning",
                        mapKeyMessage:              "DNSSEC partially configured - DNSKEY exists but DS record missing at registrar",
                        mapKeyHasDnskey:            true,
                        mapKeyHasDs:                false,
                        mapKeyDnskeyRecords:        p.dnskeyRecords,
                        mapKeyDsRecords:            []string{},
                        mapKeyAlgorithm:            nil,
                        mapKeyAlgorithmName:        nil,
                        mapKeyAlgorithmObservation: nil,
                        mapKeyChainOfTrust:         "broken",
                        mapKeyAdFlag:               false,
                        mapKeyAdConsensus:          p.adState,
                        mapKeyResolverAD:           p.resolverAD,
                        mapKeyAdResolver:           derefStr(p.adResolver),
                        // Signed zone with no DS at the parent = island of security / broken
                        // chain, NOT "present". AnalyzeDNSSEC only reaches this branch after an
                        // authoritative parent confirmation, so the absence is real, never a
                        // consensus-miss fabrication (RFC 4035 §3.2.3, RFC 6781 §4.2.2).
                        mapKeyDnssecState: dnssecStatePartial,
                        mapKeyDisplayLabel:         label,
                        mapKeyDisplaySeverity:      severity,
                }
        }

        label, severity := dnssecDisplayLabel(dnssecStateAbsentConf, "none")
        return map[string]any{
                mapKeyStatus:               "warning",
                mapKeyMessage:              "DNSSEC not configured - DNS responses are unsigned",
                mapKeyHasDnskey:            false,
                mapKeyHasDs:                false,
                mapKeyDnskeyRecords:        []string{},
                mapKeyDsRecords:            []string{},
                mapKeyAlgorithm:            nil,
                mapKeyAlgorithmName:        nil,
                mapKeyAlgorithmObservation: nil,
                mapKeyChainOfTrust:         "none",
                mapKeyAdFlag:               false,
                mapKeyAdConsensus:          p.adState,
                mapKeyResolverAD:           p.resolverAD,
                mapKeyAdResolver:           nil,
                mapKeyDnssecState:          dnssecStateAbsentConf,
                mapKeyDisplayLabel:         label,
                mapKeyDisplaySeverity:      severity,
        }
}

// buildIndeterminateDNSSECResult renders the honest "could not verify" verdict
// when DNSKEY/DS lookups failed transiently and the resolver did not set the AD
// flag. Per RFC 4035, the absence of signing material can only be asserted from
// an authoritative answer — never from a failed lookup — so this is explicitly
// NOT a finding of "unsigned".
func buildIndeterminateDNSSECResult(adResolver *string) map[string]any {
        label, severity := dnssecDisplayLabel(dnssecStateIndeterminate, statusUnknown)
        return map[string]any{
                mapKeyStatus:               statusUnknown,
                mapKeyMessage:              "DNSSEC could not be verified — DNSKEY/DS lookups did not complete (transient resolver failure). This is not evidence that DNSSEC is absent (RFC 4035).",
                mapKeyHasDnskey:            false,
                mapKeyHasDs:                false,
                mapKeyDnskeyRecords:        []string{},
                mapKeyDsRecords:            []string{},
                mapKeyAlgorithm:            nil,
                mapKeyAlgorithmName:        nil,
                mapKeyAlgorithmObservation: nil,
                mapKeyChainOfTrust:         statusUnknown,
                mapKeyAdFlag:               false,
                mapKeyAdResolver:           derefStr(adResolver),
                mapKeyDnssecState:          dnssecStateIndeterminate,
                mapKeyDisplayLabel:         label,
                mapKeyDisplaySeverity:      severity,
        }
}

// buildUnmeasuredDNSSECResult renders the honest "never measured" verdict when
// the parent scan deadline expired before DNSSEC could be measured. This is a
// DIFFERENT claim from "indeterminate" (which means "we measured and the
// protocol cannot say"): here we never got to measure at all, so it belongs on
// the unmeasured counter and must never merge into honest-uncertainty.
func buildUnmeasuredDNSSECResult(reason string) map[string]any {
        label, severity := dnssecDisplayLabel(dnssecStateUnmeasured, statusUnknown)
        return map[string]any{
                mapKeyStatus:               statusUnknown,
                mapKeyMessage:              "DNSSEC measurement deferred — the scan deadline expired before DNSSEC could be measured. This is not a claim about the domain's DNSSEC state; re-run the scan to measure it.",
                mapKeyHasDnskey:            false,
                mapKeyHasDs:                false,
                mapKeyDnskeyRecords:        []string{},
                mapKeyDsRecords:            []string{},
                mapKeyAlgorithm:            nil,
                mapKeyAlgorithmName:        nil,
                mapKeyAlgorithmObservation: nil,
                mapKeyChainOfTrust:         statusUnknown,
                mapKeyAdFlag:               false,
                mapKeyAdResolver:           nil,
                mapKeyDnssecState:          dnssecStateUnmeasured,
                mapKeyUnmeasuredReason:     reason,
                mapKeyDisplayLabel:         label,
                mapKeyDisplaySeverity:      severity,
        }
}

func collectDNSKEYRecords(results []string) (bool, []string) {
        if len(results) == 0 {
                return false, nil
        }
        var records []string
        for i, rec := range results {
                if i >= 3 {
                        break
                }
                if len(rec) > 100 {
                        records = append(records, rec[:100]+"...")
                } else {
                        records = append(records, rec)
                }
        }
        return true, records
}

func collectDSRecords(results []string) (bool, []string) {
        if len(results) == 0 {
                return false, nil
        }
        var records []string
        for i, rec := range results {
                if i >= 3 {
                        break
                }
                records = append(records, rec)
        }
        return true, records
}

func parentDSRecords(a *Analyzer, ctx context.Context, parentZone string) []string {
        if parentZone == "" {
                return nil
        }
        return a.DNS.QueryDNS(ctx, "DS", parentZone)
}

// parentDSState is the authoritative confirmation result for a child zone's DS
// RRset, queried directly at the PARENT zone's nameservers (recursion disabled).
// Per RFC 4035 §3.1.4 the DS RRset is published in the PARENT zone, and per
// RFC 4035 §3.2.3 / RFC 6781 §4.2.2 the ABSENCE of a DS may only be asserted
// from the parent's authoritative answer — never inferred from a recursive or
// multi-resolver consensus miss (stale cache, RRSIG filtering, resolver
// disagreement), which would fabricate a "DS missing at registrar" verdict
// against a zone whose chain of trust is in fact intact.
type parentDSState int

const (
        parentDSIndeterminate parentDSState = iota
        parentDSConfirmedPresent
        parentDSConfirmedAbsent
)

type parentDSConfirmation struct {
        state   parentDSState
        records []string
}

// queryParentAuthoritativeDS resolves the parent zone's nameservers and queries
// the child's DS RRset directly at a parent server with recursion disabled. A
// non-empty DS answer confirms presence; a NOERROR/empty answer from the parent
// authoritative server confirms genuine absence (island of security, RFC 6781
// §4.2.2); any parent-discovery, transport, server-failure (SERVFAIL/REFUSED),
// or non-authoritative (AA=0) result leaves the outcome indeterminate ("could
// not verify") rather than asserting a broken chain.
func (a *Analyzer) queryParentAuthoritativeDS(ctx context.Context, domain string) parentDSConfirmation {
        parentZone := parentZoneFromDomain(domain)
        if parentZone == "" {
                return parentDSConfirmation{state: parentDSIndeterminate}
        }

        parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
        if len(parentNSServers) == 0 {
                return parentDSConfirmation{state: parentDSIndeterminate}
        }

        parentServer := strings.TrimRight(parentNSServers[0], ".")
        parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
        if len(parentIPs) == 0 {
                return parentDSConfirmation{state: parentDSIndeterminate}
        }

        records, authoritative, status := a.DNS.QuerySpecificResolverAuth(ctx, "DS", domain, parentIPs[0])
        // Absence of a DS may only be asserted from an AUTHORITATIVE parent answer
        // (RFC 4035 §3.2.3, RFC 6781 §4.2.2). A SERVFAIL/REFUSED/FORMERR/timeout
        // (status != "") carries no answer section, and a NOERROR that is not
        // authoritative (AA=0) means we never reached a parent authority — both must
        // stay indeterminate rather than fabricating a broken chain. An NXDOMAIN for
        // a child whose DNSKEY we already observed is self-contradictory, so it too
        // is treated as could-not-verify, never a confirmed absence.
        if status != "" || !authoritative {
                return parentDSConfirmation{state: parentDSIndeterminate}
        }
        if has, ds := collectDSRecords(records); has {
                return parentDSConfirmation{state: parentDSConfirmedPresent, records: ds}
        }
        return parentDSConfirmation{state: parentDSConfirmedAbsent}
}

func buildInheritedDNSSECResult(parentZone string, adResolver *string, parentAlgo *int, parentAlgoName *string) map[string]any {
        var message string
        if parentZone != "" {
                message = fmt.Sprintf("DNSSEC inherited from parent zone (%s) - DNS responses are authenticated", parentZone)
        } else {
                message = "DNSSEC validated by resolver - DNS responses are authenticated"
        }
        label, severity := dnssecDisplayLabel(dnssecStatePresent, "inherited")
        return map[string]any{
                mapKeyStatus:               "success",
                mapKeyMessage:              message,
                mapKeyHasDnskey:            false,
                mapKeyHasDs:                false,
                mapKeyDnskeyRecords:        []string{},
                mapKeyDsRecords:            []string{},
                mapKeyAlgorithm:            derefInt(parentAlgo),
                mapKeyAlgorithmName:        derefStr(parentAlgoName),
                mapKeyAlgorithmObservation: algorithmObservation(parentAlgo),
                mapKeyChainOfTrust:         "inherited",
                mapKeyAdFlag:               true,
                mapKeyAdResolver:           derefStr(adResolver),
                mapKeyDnssecState:          dnssecStatePresent,
                mapKeyDisplayLabel:         label,
                mapKeyDisplaySeverity:      severity,
                "is_subdomain":             true,
                "parent_zone":              parentZone,
        }
}

func (a *Analyzer) AnalyzeDNSSEC(ctx context.Context, domain string) map[string]any {
        // Deferred guard: if the parent scan deadline is already exhausted, the
        // DNSKEY/DS/AD lookups below would fail with transient errors and fold to a
        // false "indeterminate" ("we measured and couldn't tell"). Report "unmeasured"
        // instead — we never got to measure — so honest-uncertainty isn't polluted by
        // deadline starvation (mirrors the CT subdomain task's
        // parent_deadline_exhausted guard).
        //
        // Reachability note: the "parent" context is the 60s re-wrap the orchestrator
        // applies inside AnalyzeDomain (orchestrator.go:91), not the 90s handler
        // scanContext. The shared fan-out dispatches this task at scan start — inside
        // that 60s context, before the budget is gone — so this entry guard is
        // structurally near-unreachable in production: on a within-budget scan the
        // deadline hasn't passed yet, and on an overrun the goroutine is already
        // running. The post-lookup guard below (ctx.Err() == DeadlineExceeded) is the
        // one that fires when the budget expires mid-scan. This guard still earns its
        // place: it defends a direct call with an already-expired context (the
        // unit-test path) and keeps "never fabricate a verdict from a cancelled
        // context" true at the boundary.
        if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 0 {
                return buildUnmeasuredDNSSECResult("entry_deadline")
        }

        dnskeyRec, dnskeyStatus := a.DNS.QueryDNSWithTTLStatus(ctx, "DNSKEY", domain, true)
        hasDNSKEY, dnskeyRecords := collectDNSKEYRecords(dnskeyRec.Records)
        dsRec, dsStatus := a.DNS.QueryDNSWithTTLStatus(ctx, "DS", domain, true)
        hasDS, dsRecords := collectDSRecords(dsRec.Records)

        adResult := a.DNS.CheckDNSSECADFlag(ctx, domain)
        adFlag := adResult.ADFlag
        adState := adResult.State
        resolverAD := adResult.ResolverAD
        adResolver := adResult.ResolverUsed

        // If the parent deadline expired DURING the lookups, the transient
        // failures are deadline-induced, not resolver failures — report
        // "unmeasured" rather than "indeterminate" (a measurement interrupted
        // by deadline starvation is not a "couldn't tell" verdict).
        if ctx.Err() == context.DeadlineExceeded {
                return buildUnmeasuredDNSSECResult("postlookup_deadline")
        }

        algorithm, algorithmName := parseAlgorithm(dsRecords)

        // Honest tri-state: a transient DNSKEY/DS lookup failure must never be read
        // as "not configured" (no records) OR as "DS missing at registrar" (partial)
        // for the half that failed. If EITHER lookup errored and we lack definitive
        // positive evidence — a full DNSKEY+DS pair, or a resolver AD flag confirming
        // the chain of trust — we genuinely cannot tell signed from unsigned, so we
        // report indeterminate rather than fabricating an absence-style verdict.
        // Covers the mixed cases too (e.g. DNSKEY errored while DS resolved, or DS
        // errored while DNSKEY resolved), which the old !hasDNSKEY && !hasDS guard
        // let fall through to "not configured" / "partial" (RFC 4035 — absence is
        // only assertable from an authoritative answer, never a failed lookup).
        lookupErrored := dnskeyStatus == dnsclient.LookupError || dsStatus == dnsclient.LookupError ||
                dnskeyStatus == dnsclient.LookupConflict || dsStatus == dnsclient.LookupConflict
        definitivePositive := (hasDNSKEY && hasDS) || adFlag
        if lookupErrored && !definitivePositive {
                return buildIndeterminateDNSSECResult(adResolver)
        }

        // Consistency guard: a resolver reporting "secure" (validated chain),
        // "bogus" (broken chain), or "split" (disagreeing validators) necessarily
        // saw and evaluated the DNSKEY/DS records — it cannot validate a chain it
        // never saw. An empty DNSKEY OR DS lookup beside such a state is a
        // false-negative from our own consensus fold, never a real absence. Refuse
        // to assert "absent_confirmed" (empty DNSKEY) or "partial"/"broken" (empty
        // DS) when the AD signal proves the chain, so a row can never store a
        // contradiction beside "ad_consensus: secure/bogus/split".
        //
        // EXCEPTION — inherited signing: a SUBDOMAIN of a signed zone legitimately
        // has no DNSKEY/DS of its own (signing lives at the parent apex), so
        // "secure AD + empty DNSKEY/DS" is the inherited case, not a false-absent
        // contradiction. The guard applies to the zone apex only; a secure subdomain
        // falls through to buildInheritedDNSSECResult below. (A bogus/split AD on a
        // subdomain is the broken-parent case, which is not inherited-valid signing,
        // so the guard still applies there.)
        inheritedZone := ""
        if (!hasDNSKEY || !hasDS) && adState == "secure" {
                inheritedZone = findParentZone(a.DNS, ctx, domain)
        }
        if (!hasDNSKEY || !hasDS) && (adState == "secure" || adState == "bogus" || adState == "split") && inheritedZone == "" {
                return buildIndeterminateDNSSECResult(adResolver)
        }

        // hasDNSKEY && !hasDS from the recursive/consensus path is the classic
        // false-absence: the DS RRset lives in the PARENT zone, so a consensus miss
        // (stale cache, RRSIG filtering, resolver disagreement) must never be reported
        // as "DS missing at registrar". When the resolver did not independently set the
        // AD flag (no proof of a complete chain), confirm the DS directly at the
        // parent's authoritative servers before asserting a broken chain. Present →
        // adopt the real DS; authoritatively absent → genuine island of security;
        // unconfirmable → indeterminate, never a fabricated absence (RFC 4035 §3.2.3,
        // RFC 6781 §4.2.2).
        if hasDNSKEY && !hasDS && !adFlag {
                switch confirm := a.queryParentAuthoritativeDS(ctx, domain); confirm.state {
                case parentDSConfirmedPresent:
                        hasDS = true
                        dsRecords = confirm.records
                        algorithm, algorithmName = parseAlgorithm(confirm.records)
                case parentDSIndeterminate:
                        return buildIndeterminateDNSSECResult(adResolver)
                case parentDSConfirmedAbsent:
                        // Real DNSKEY-without-DS, authoritatively confirmed at the parent. Fall
                        // through to buildDNSSECResult, which now labels dnssec_state=partial.
                }
        }

        if !adFlag || hasDNSKEY || hasDS {
                return buildDNSSECResult(dnssecParams{
                        hasDNSKEY:     hasDNSKEY,
                        hasDS:         hasDS,
                        adState:       adState,
                        resolverAD:    resolverAD,
                        dnskeyRecords: dnskeyRecords,
                        dsRecords:     dsRecords,
                        algorithm:     algorithm,
                        algorithmName: algorithmName,
                        adResolver:    adResolver,
                })
        }

        // Inherited signing: a subdomain of a signed zone. inheritedZone was
        // resolved by the guard above (secure AD + empty own DNSKEY/DS); resolve
        // it now only for the defensive direct-call path.
        if inheritedZone == "" {
                inheritedZone = findParentZone(a.DNS, ctx, domain)
        }
        parentAlgo, parentAlgoName := parseAlgorithm(parentDSRecords(a, ctx, inheritedZone))

        return buildInheritedDNSSECResult(inheritedZone, adResolver, parentAlgo, parentAlgoName)
}
