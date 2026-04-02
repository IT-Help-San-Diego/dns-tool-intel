//go:build intel

// dns-tool:scrutiny science
// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full intelligence implementation.
package analyzer

const (
	nameOnDMARC       = "OnDMARC"
	nameDMARCReport   = "DMARC Report"
	nameDMARCLY       = "DMARCLY"
	nameDmarcian      = "Dmarcian"
	nameSendmarc      = "Sendmarc"
	nameProofpoint    = "Proofpoint"
	nameValimailEnf   = "Valimail Enforce"
	nameProofpointEFD = "Proofpoint EFD"
	namePowerDMARC    = "PowerDMARC"
	nameMailhardener  = "Mailhardener"
	nameFraudmarc     = "Fraudmarc"
	nameEasyDMARC     = "EasyDMARC"
	nameDMARCAdvisor  = "DMARC Advisor"
	nameRedSift       = "Red Sift"

	vendorRedSift    = "Red Sift"
	vendorValimail   = "Valimail"
	vendorDmarcian   = "Dmarcian"
	vendorSendmarc   = "Sendmarc"
	vendorProofpoint = "Proofpoint"
	vendorDMARCLY    = "DMARCLY"
	vendorPowerDMARC = "PowerDMARC"
	vendorFraudmarc  = "Fraudmarc"
	vendorEasyDMARC  = "EasyDMARC"
	vendorDMARCAdv   = "DMARC Advisor"
	vendorMailharden = "Mailhardener"
	vendorDMARCRpt   = "DMARC Report"
	vendorFortra     = "Fortra"
	vendorMimecast   = "Mimecast"
	vendorActiveCamp = "ActiveCampaign"

	nameAkamai     = "Akamai"
	nameSalesforce = "Salesforce"
	nameHubSpot    = "HubSpot"
	nameHeroku     = "Heroku"

	domainOndmarc  = "ondmarc.com"
	domainRedsift  = "redsift.cloud"
	domainDmarcian = "dmarcian.com"
	domainSendmarc = "sendmarc.com"
)

// Stub: populated by dnstool-intel private repo at build time (see CONTRIBUTING.md §Provider Intelligence).
var dmarcMonitoringProviders = map[string]managementProviderInfo{}

// Stub: populated by dnstool-intel private repo at build time (see CONTRIBUTING.md §Provider Intelligence).
var spfFlatteningProviders = map[string]spfFlatteningInfo{}

// Stub: populated by dnstool-intel private repo at build time (see CONTRIBUTING.md §Provider Intelligence).
var hostedDKIMProviders = map[string]hostedDKIMInfo{}

// Stub: populated by dnstool-intel private repo at build time (see CONTRIBUTING.md §Provider Intelligence).
var dynamicServicesProviders = map[string]dynamicServiceInfo{}

// Stub: populated by dnstool-intel private repo at build time (see CONTRIBUTING.md §Provider Intelligence).
var dynamicServicesZones = map[string]string{}

// Stub: populated by dnstool-intel private repo at build time (see CONTRIBUTING.md §Provider Intelligence).
var cnameProviderMap = map[string]cnameProviderInfo{}

// Stub: full intelligence implementation in dnstool-intel private repo.
func isHostedEmailProvider(_ string) bool {
	return true
}

// Stub: full intelligence implementation in dnstool-intel private repo.
func isBIMICapableProvider(_ string) bool {
	return false
}

// Stub: full intelligence implementation in dnstool-intel private repo.
func isKnownDKIMProvider(_ interface{}) bool {
	return false
}
