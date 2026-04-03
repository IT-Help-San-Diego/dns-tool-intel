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

// Intel-boundary: populated from dns-tool-intel private repo at build time.
var dmarcMonitoringProviders = map[string]managementProviderInfo{}

// Intel-boundary: populated from dns-tool-intel private repo at build time.
var spfFlatteningProviders = map[string]spfFlatteningInfo{}

// Intel-boundary: populated from dns-tool-intel private repo at build time.
var hostedDKIMProviders = map[string]hostedDKIMInfo{}

// Intel-boundary: populated from dns-tool-intel private repo at build time.
var dynamicServicesProviders = map[string]dynamicServiceInfo{}

// Intel-boundary: populated from dns-tool-intel private repo at build time.
var dynamicServicesZones = map[string]string{}

// Intel-boundary: populated from dns-tool-intel private repo at build time.
var cnameProviderMap = map[string]cnameProviderInfo{}

// Intel-boundary: full implementation provided by dns-tool-intel at build time.
func isHostedEmailProvider(_ string) bool {
	return true
}

// Intel-boundary: full implementation provided by dns-tool-intel at build time.
func isBIMICapableProvider(_ string) bool {
	return false
}

// Intel-boundary: full implementation provided by dns-tool-intel at build time.
func isKnownDKIMProvider(_ interface{}) bool {
	return false
}
