// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "fmt"

type DKIMState int

const (
	// DKIMInconclusive is the zero value so an unassigned or zero-valued
	// DKIMState defaults to the HONEST state ("could not determine") rather
	// than DKIMAbsent — which the classifier can no longer produce and which
	// would wrongly read as a positive "no DKIM" claim (and route to the
	// now-removed NeedsAction).
	DKIMInconclusive DKIMState = iota
	DKIMAbsent
	DKIMSuccess
	DKIMProviderInferred
	DKIMThirdPartyOnly
	DKIMWeakKeysOnly
	DKIMNoMailDomain
)

func (s DKIMState) String() string {
	switch s {
	case DKIMAbsent:
		return "absent"
	case DKIMSuccess:
		return "success"
	case DKIMProviderInferred:
		return "provider_inferred"
	case DKIMThirdPartyOnly:
		return "third_party_only"
	case DKIMInconclusive:
		return "inconclusive"
	case DKIMWeakKeysOnly:
		return "weak_keys_only"
	case DKIMNoMailDomain:
		return "no_mail_domain"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

func (s DKIMState) IsPresent() bool {
	switch s {
	case DKIMSuccess, DKIMProviderInferred, DKIMThirdPartyOnly, DKIMWeakKeysOnly:
		return true
	}
	return false
}

func (s DKIMState) IsConfigured() bool {
	switch s {
	case DKIMSuccess, DKIMProviderInferred, DKIMThirdPartyOnly:
		return true
	}
	return false
}

func (s DKIMState) NeedsMonitoring() bool {
	return s == DKIMInconclusive
}

func classifyDKIMState(ps protocolState) DKIMState {
	if ps.isNoMailDomain {
		return DKIMNoMailDomain
	}
	if ps.dkimOK {
		return DKIMSuccess
	}
	if ps.dkimProvider {
		return DKIMProviderInferred
	}
	if ps.dkimPartial || ps.dkimThirdPartyOnly {
		return DKIMThirdPartyOnly
	}
	if ps.dkimWeakKeys {
		return DKIMWeakKeysOnly
	}
	// No selector matched on a mail domain. DKIM selectors are arbitrary
	// labels with no enumerating DNS record (RFC 6376), so "nothing found at
	// any probed selector" is INCONCLUSIVE — it proves only that the domain
	// does not use THOSE names, never that it does not sign. Reporting it as
	// DKIMAbsent would count a guess as a measurement.
	return DKIMInconclusive
}
