// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	domainkeySuffix              = "._domainkey"
	ancillaryServicesLikelyFmt   = "The %s SPF include likely supports ancillary services "
	ancillaryServicesDescription = "(e.g., calendar invitations, shared documents) rather than primary mailbox hosting."
)

const (
	providerMicrosoft365    = "Microsoft 365"
	providerGoogleWS        = "Google Workspace"
	providerMailChimp       = "MailChimp"
	providerSendGrid        = "SendGrid"
	providerMailjet         = "Mailjet"
	providerAmazonSES       = "Amazon SES"
	providerPostmark        = "Postmark"
	providerSparkPost       = "SparkPost"
	providerMailgun         = "Mailgun"
	providerBrevo           = "Brevo (Sendinblue)"
	providerMimecast        = "Mimecast"
	providerProofpoint      = "Proofpoint"
	providerZohoMail        = "Zoho Mail"
	providerFastmail        = "Fastmail"
	providerProtonMail      = "ProtonMail"
	providerCloudflareEmail = "Cloudflare Email"
	providerBarracuda       = "Barracuda"
	providerHornetsecurity  = "Hornetsecurity"
	providerSpamExperts     = "SpamExperts"
	providerZendesk         = "Zendesk"
	providerUnknown         = "Unknown"
	providerDrip            = "Drip"

	selDefault     = "default._domainkey"
	selDKIM        = "dkim._domainkey"
	selMail        = "mail._domainkey"
	selEmail       = "email._domainkey"
	selK1          = "k1._domainkey"
	selK2          = "k2._domainkey"
	selS1          = "s1._domainkey"
	selS2          = "s2._domainkey"
	selSig1        = "sig1._domainkey"
	selSelector1   = "selector1._domainkey"
	selSelector2   = "selector2._domainkey"
	selGoogle      = "google._domainkey"
	selGoogle2048  = "google2048._domainkey"
	selMailjet     = "mailjet._domainkey"
	selMandrill    = "mandrill._domainkey"
	selAmazonSES   = "amazonses._domainkey"
	selSendgrid    = "sendgrid._domainkey"
	selMailchimp   = "mailchimp._domainkey"
	selPostmark    = "postmark._domainkey"
	selSparkpost   = "sparkpost._domainkey"
	selMailgun     = "mailgun._domainkey"
	selSendinblue  = "sendinblue._domainkey"
	selMimecast    = "mimecast._domainkey"
	selProofpoint  = "proofpoint._domainkey"
	selEverlytic   = "everlytickey1._domainkey"
	selZendesk1    = "zendesk1._domainkey"
	selZendesk2    = "zendesk2._domainkey"
	selCM          = "cm._domainkey"
	selMX          = "mx._domainkey"
	selSMTP        = "smtp._domainkey"
	selMailer      = "mailer._domainkey"
	selProtonmail  = "protonmail._domainkey"
	selProtonmail2 = "protonmail2._domainkey"
	selProtonmail3 = "protonmail3._domainkey"
	selFM1         = "fm1._domainkey"
	selFM2         = "fm2._domainkey"
	selFM3         = "fm3._domainkey"

	selZoho     = "zoho._domainkey"
	selZohoMail = "zohomail._domainkey"
	selZmail    = "zmail._domainkey"
	selSquare   = "square._domainkey"
	selSquareup = "squareup._domainkey"
	selSQ       = "sq._domainkey"

	selDKIM1          = "dkim1._domainkey"
	selDKIM2          = "dkim2._domainkey"
	selDKIM3          = "dkim3._domainkey"
	selKey1           = "key1._domainkey"
	selKey2           = "key2._domainkey"
	selSig2           = "sig2._domainkey"
	selS3             = "s3._domainkey"
	selK3             = "k3._domainkey"
	selSelector3      = "selector3._domainkey"
	selBrevo          = "brevo._domainkey"
	selMTA            = "mta._domainkey"
	selMTA1           = "mta1._domainkey"
	selMTA2           = "mta2._domainkey"
	selSendgrid2      = "sendgrid2._domainkey"
	selSmtpapi        = "smtpapi._domainkey"
	selEM             = "em._domainkey"
	selBarracuda      = "barracuda._domainkey"
	selHornet         = "hornet._domainkey"
	selCiscoDKIM      = "cisco._domainkey"
	selTurbo          = "turbo-smtp._domainkey"
	selFreshdesk      = "freshdesk._domainkey"
	selHubspot        = "hubspot._domainkey"
	selHS1            = "hs1._domainkey"
	selHS2            = "hs2._domainkey"
	selSalesforce     = "salesforce._domainkey"
	selSF1            = "sf1._domainkey"
	selSF2            = "sf2._domainkey"
	selMandrill2      = "mandrill2._domainkey"
	selKlaviyo        = "klaviyo._domainkey"
	selIntercom       = "intercom._domainkey"
	selCustomerio     = "customerio._domainkey"
	selConstContact   = "ctct1._domainkey"
	selConstContact2  = "ctct2._domainkey"
	selActiveCampaign = "dk._domainkey"
	selMailchimp2     = "mc._domainkey"
	selMailerLite     = "ml._domainkey"
	selDrip           = "drip._domainkey"
	selEverlyticKey2  = "everlytickey2._domainkey"

	providerSquareOnline    = "Square Online"
	providerCustomerIO      = "Customer.io"
	providerConstantContact = "Constant Contact"

	mapKeyKeyBits     = "key_bits"
	mapKeyProvider    = "provider"
	mapKeyRevoked     = "revoked"
	mapKeyDkimState   = "dkim_state"
	strActivecampaign = "ActiveCampaign"
	strEverlytic      = "Everlytic"
	strFreshdesk      = "Freshdesk"
	strHubspot        = "HubSpot"
	strIntercom       = "Intercom"
	strKlaviyo        = "Klaviyo"
	strMailerlite     = "MailerLite"
	strSalesforce     = "Salesforce"
)

var (
	dkimKeyTypeRe  = regexp.MustCompile(`(?i)\bk=(\w+)`)
	dkimPKeyRe     = regexp.MustCompile(`(?i)\bp=([^;\s]*)`)
	dkimTestFlagRe = regexp.MustCompile(`(?i)\bt=y\b`)
)

var defaultDKIMSelectors = []string{
	selDefault, selDKIM, selMail,
	selEmail, selK1, selK2, selK3,
	selS1, selS2, selS3, selSig1, selSig2,
	selSelector1, selSelector2, selSelector3,
	selGoogle, selGoogle2048,
	selMailjet, selMandrill, selMandrill2, selAmazonSES,
	selSendgrid, selSendgrid2, selSmtpapi, selEM,
	selMailchimp, selMailchimp2, selPostmark,
	selSparkpost, selMailgun, selSendinblue, selBrevo,
	selMimecast, selProofpoint, selEverlytic, selEverlyticKey2,
	selZendesk1, selZendesk2, selCM,
	selMX, selSMTP, selMailer, selMTA, selMTA1, selMTA2,
	selProtonmail, selProtonmail2, selProtonmail3,
	selFM1, selFM2, selFM3,
	selZoho, selZohoMail, selZmail,
	selSquare, selSquareup, selSQ,
	selDKIM1, selDKIM2, selDKIM3,
	selKey1, selKey2,
	selBarracuda, selHornet, selCiscoDKIM, selTurbo,
	selFreshdesk, selHubspot, selHS1, selHS2,
	selSalesforce, selSF1, selSF2,
	selKlaviyo, selIntercom, selCustomerio,
	selConstContact, selConstContact2,
	selActiveCampaign, selMailerLite, selDrip,
}

var selectorProviderMap = map[string]string{
	selSelector1:      providerMicrosoft365,
	selSelector2:      providerMicrosoft365,
	selGoogle:         providerGoogleWS,
	selGoogle2048:     providerGoogleWS,
	selK1:             providerMailChimp,
	selK2:             providerMailChimp,
	"k3._domainkey":   providerMailChimp,
	selMailchimp:      providerMailChimp,
	selMandrill:       "MailChimp (Mandrill)",
	selS1:             providerSendGrid,
	selS2:             providerSendGrid,
	selSendgrid:       providerSendGrid,
	selMailjet:        providerMailjet,
	selAmazonSES:      providerAmazonSES,
	selPostmark:       providerPostmark,
	selSparkpost:      providerSparkPost,
	selMailgun:        providerMailgun,
	selSendinblue:     providerBrevo,
	selMimecast:       providerMimecast,
	selProofpoint:     providerProofpoint,
	selEverlytic:      strEverlytic,
	selEverlyticKey2:  strEverlytic,
	selZendesk1:       providerZendesk,
	selZendesk2:       providerZendesk,
	selCM:             "Campaign Monitor",
	selZoho:           providerZohoMail,
	selZohoMail:       providerZohoMail,
	selZmail:          providerZohoMail,
	selSquare:         providerSquareOnline,
	selSquareup:       providerSquareOnline,
	selSQ:             providerSquareOnline,
	selBrevo:          providerBrevo,
	selSendgrid2:      providerSendGrid,
	selSmtpapi:        providerSendGrid,
	selEM:             providerSendGrid,
	selMandrill2:      "MailChimp (Mandrill)",
	selMailchimp2:     providerMailChimp,
	selBarracuda:      providerBarracuda,
	selHornet:         providerHornetsecurity,
	selFreshdesk:      strFreshdesk,
	selHubspot:        strHubspot,
	selHS1:            strHubspot,
	selHS2:            strHubspot,
	selSalesforce:     strSalesforce,
	selSF1:            strSalesforce,
	selSF2:            strSalesforce,
	selKlaviyo:        strKlaviyo,
	selIntercom:       strIntercom,
	selCustomerio:     providerCustomerIO,
	selConstContact:   providerConstantContact,
	selConstContact2:  providerConstantContact,
	selActiveCampaign: strActivecampaign,
	selMailerLite:     strMailerlite,
	selDrip:           providerDrip,
}

var mxToDKIMProvider = map[string]string{
	"google":             providerGoogleWS,
	"googlemail":         providerGoogleWS,
	"gmail":              providerGoogleWS,
	"outlook":            providerMicrosoft365,
	"microsoft":          providerMicrosoft365,
	"protection.outlook": providerMicrosoft365,
	"o365":               providerMicrosoft365,
	"exchange":           providerMicrosoft365,
	"intermedia":         providerMicrosoft365,
	"pphosted":           providerProofpoint,
	"gpphosted":          providerProofpoint,
	"iphmx":              providerProofpoint,
	"mimecast":           providerMimecast,
	"barracudanetworks":  providerBarracuda,
	"barracuda":          providerBarracuda,
	"perception-point":   "Perception Point",
	"sophos":             "Sophos",
	"fireeyecloud":       "FireEye",
	"trendmicro":         "Trend Micro",
	"forcepoint":         "Forcepoint",
	"messagelabs":        "Symantec",
	"hornetsecurity":     providerHornetsecurity,
	"antispamcloud":      providerSpamExperts,
	"spamexperts":        providerSpamExperts,
	"zoho":               providerZohoMail,
	"mailgun":            providerMailgun,
	"sendgrid":           providerSendGrid,
	"amazonses":          providerAmazonSES,
	"fastmail":           providerFastmail,
	"protonmail":         providerProtonMail,
	"mx.cloudflare":      providerCloudflareEmail,
}

var securityGateways = map[string]bool{
	providerProofpoint: true, providerMimecast: true, providerBarracuda: true,
	"Perception Point": true, "Sophos": true, "FireEye": true,
	"Trend Micro": true, "Forcepoint": true, "Symantec": true,
	providerHornetsecurity: true, providerSpamExperts: true,
}

var mailboxProviders = map[string]bool{
	providerMicrosoft365:    true,
	providerGoogleWS:        true,
	providerZohoMail:        true,
	providerFastmail:        true,
	providerProtonMail:      true,
	providerCloudflareEmail: true,
}

var primaryProviderSelectors = map[string][]string{
	providerMicrosoft365:    {selSelector1, selSelector2, selSelector3},
	providerGoogleWS:        {selGoogle, selGoogle2048},
	providerProofpoint:      {selProofpoint},
	providerMimecast:        {selMimecast},
	providerMailgun:         {selMailgun},
	providerSendGrid:        {selS1, selS2, selS3, selSendgrid, selSendgrid2, selSmtpapi, selEM},
	providerAmazonSES:       {selAmazonSES},
	providerZohoMail:        {selZoho, selZohoMail, selZmail, selDefault},
	providerFastmail:        {selFM1, selFM2, selFM3},
	providerProtonMail:      {selProtonmail, selProtonmail2, selProtonmail3},
	providerCloudflareEmail: {selDefault},
	providerBarracuda:       {selBarracuda},
	providerHornetsecurity:  {selHornet},
	providerBrevo:           {selBrevo, selSendinblue},
	providerMailChimp:       {selMailchimp, selMailchimp2, selK1, selK2, selK3, selMandrill, selMandrill2},
	providerMailjet:         {selMailjet},
	providerPostmark:        {selPostmark},
	providerSparkPost:       {selSparkpost},
	providerZendesk:         {selZendesk1, selZendesk2},
	strHubspot:              {selHubspot, selHS1, selHS2},
	strSalesforce:           {selSalesforce, selSF1, selSF2},
	strKlaviyo:              {selKlaviyo},
	strIntercom:             {selIntercom},
	providerCustomerIO:      {selCustomerio},
	providerConstantContact: {selConstContact, selConstContact2},
	strActivecampaign:       {selActiveCampaign},
	strMailerlite:           {selMailerLite},
	providerDrip:            {selDrip},
	strFreshdesk:            {selFreshdesk},
	strEverlytic:            {selEverlytic, selEverlyticKey2},
}

var spfMailboxProviders = map[string]string{
	"spf.protection.outlook": providerMicrosoft365,
	"_spf.google":            providerGoogleWS,
	"spf.intermedia":         providerMicrosoft365,
	"emg.intermedia":         providerMicrosoft365,
	"zoho.com":               providerZohoMail,
	"messagingengine.com":    providerFastmail,
	"protonmail.ch":          providerProtonMail,
	"mimecast":               providerMimecast,
	"pphosted":               providerProofpoint,
}

var spfAncillarySenders = map[string]string{
	"servers.mcsv.net":    providerMailChimp,
	"spf.mandrillapp":     providerMailChimp,
	"sendgrid.net":        providerSendGrid,
	"amazonses.com":       providerAmazonSES,
	"mailgun.org":         providerMailgun,
	"spf.sparkpostmail":   providerSparkPost,
	"mail.zendesk.com":    providerZendesk,
	"spf.brevo.com":       providerBrevo,
	"spf.sendinblue":      providerBrevo,
	"spf.mailjet":         providerMailjet,
	"spf.postmarkapp":     providerPostmark,
	"spf.mtasv.net":       providerPostmark,
	"spf.freshdesk":       strFreshdesk,
	"hostedrt.com":        "Best Practical RT",
	"hubspot.net":         strHubspot,
	"spf.salesforce.com":  strSalesforce,
	"spf1.klaviyo.com":    strKlaviyo,
	"intercom.io":         strIntercom,
	"spf.customerio":      providerCustomerIO,
	"spf.constantcontact": providerConstantContact,
	"emsd1.com":           strActivecampaign,
	"spf.mailerlite":      strMailerlite,
	"getdrip.com":         providerDrip,
}

var ambiguousSelectors = map[string]bool{
	selSelector1: true,
	selSelector2: true,
	selS1:        true,
	selS2:        true,
	selDefault:   true,
	selK1:        true,
	selK2:        true,
}

type ProviderResolution struct {
	Primary           string
	Gateway           string
	SPFAncillaryNote  string
	DKIMInferenceNote string
	MXLegacyNote      string
}

func (pr *ProviderResolution) GatewayOrNil() interface{} {
	if pr.Gateway == "" {
		return nil
	}
	return pr.Gateway
}

func matchProviderFromRecords(records string, providerMap map[string]string) string {
	lower := strings.ToLower(records)
	for key, provider := range providerMap {
		if strings.Contains(lower, key) {
			return provider
		}
	}
	return ""
}

func detectMXProvider(mxRecords []string) string {
	if len(mxRecords) == 0 {
		return ""
	}
	return matchProviderFromRecords(strings.Join(mxRecords, " "), mxToDKIMProvider)
}

func detectSPFMailboxProvider(spfRecord string) string {
	if spfRecord == "" {
		return ""
	}
	return matchProviderFromRecords(spfRecord, spfMailboxProviders)
}

func detectSPFAncillaryProvider(spfRecord string) string {
	if spfRecord == "" {
		return ""
	}
	return matchProviderFromRecords(spfRecord, spfAncillarySenders)
}

func resolveProviderWithGateway(mxProvider, spfMailbox string) (primary, gateway string) {
	if mxProvider != "" && securityGateways[mxProvider] && spfMailbox != "" && spfMailbox != mxProvider {
		return spfMailbox, mxProvider
	}
	if mxProvider != "" {
		return mxProvider, ""
	}
	if spfMailbox != "" {
		return spfMailbox, ""
	}
	return providerUnknown, ""
}

func detectAllSPFMailboxProviders(spfRecord string) []string {
	if spfRecord == "" {
		return nil
	}
	lower := strings.ToLower(spfRecord)
	var found []string
	seen := map[string]bool{}
	for key, provider := range spfMailboxProviders {
		if strings.Contains(lower, key) && !seen[provider] {
			found = append(found, provider)
			seen[provider] = true
		}
	}
	return found
}

func detectPrimaryMailProvider(mxRecords []string, spfRecord string) ProviderResolution {
	if len(mxRecords) == 0 && spfRecord == "" {
		return ProviderResolution{Primary: providerUnknown}
	}

	mxProvider := detectMXProvider(mxRecords)
	spfProviders := detectAllSPFMailboxProviders(spfRecord)

	spfMailbox, ancillaryNote := reconcileSPFWithMX(mxProvider, spfProviders)

	spfMailbox, mxProvider, ancillaryNote = handleSelfHostedMX(spfMailbox, mxProvider, mxRecords, spfRecord, ancillaryNote)

	if spfMailbox == "" && mxProvider == "" {
		ancillary := detectSPFAncillaryProvider(spfRecord)
		if ancillary != "" {
			return ProviderResolution{Primary: providerUnknown, SPFAncillaryNote: ancillaryNote}
		}
	}

	primary, gateway := resolveProviderWithGateway(mxProvider, spfMailbox)
	mxLegacyNote := detectGoogleLegacyMX(mxRecords, mxProvider)

	return ProviderResolution{Primary: primary, Gateway: gateway, SPFAncillaryNote: ancillaryNote, MXLegacyNote: mxLegacyNote}
}

func reconcileSPFWithMX(mxProvider string, spfProviders []string) (string, string) {
	if mxProvider == "" || len(spfProviders) == 0 {
		if len(spfProviders) > 0 {
			return spfProviders[0], ""
		}
		return "", ""
	}

	var ancillaryProviders []string
	mxMatchedInSPF := false
	for _, sp := range spfProviders {
		if sp == mxProvider {
			mxMatchedInSPF = true
		} else {
			ancillaryProviders = append(ancillaryProviders, sp)
		}
	}

	if mxMatchedInSPF {
		note := ""
		if len(ancillaryProviders) > 0 {
			note = fmt.Sprintf(
				"SPF authorizes %s alongside primary mail provider %s. "+
					ancillaryServicesLikelyFmt+
					ancillaryServicesDescription,
				strings.Join(ancillaryProviders, ", "), mxProvider, strings.Join(ancillaryProviders, ", "))
		}
		return mxProvider, note
	}

	if securityGateways[mxProvider] {
		return spfProviders[0], ""
	}

	note := fmt.Sprintf(
		"SPF authorizes %s servers, but MX records point to %s. "+
			ancillaryServicesLikelyFmt+
			ancillaryServicesDescription,
		spfProviders[0], mxProvider, spfProviders[0])
	return "", note
}

func handleSelfHostedMX(spfMailbox, mxProvider string, mxRecords []string, spfRecord, ancillaryNote string) (string, string, string) {
	if spfMailbox == "" || mxProvider != "" || len(mxRecords) == 0 {
		return spfMailbox, mxProvider, ancillaryNote
	}
	ancillaryNote = fmt.Sprintf(
		"SPF authorizes %s servers, but MX records point to self-hosted infrastructure. "+
			ancillaryServicesLikelyFmt+
			ancillaryServicesDescription,
		spfMailbox, spfMailbox)
	if detectSPFAncillaryProvider(spfRecord) == "" {
		mxProvider = "Self-hosted"
	}
	return "", mxProvider, ancillaryNote
}

func detectGoogleLegacyMX(mxRecords []string, mxProvider string) string {
	if mxProvider != providerGoogleWS || len(mxRecords) < 4 {
		return ""
	}
	googleCount := 0
	for _, mx := range mxRecords {
		if strings.Contains(strings.ToLower(mx), "aspmx.l.google.com") ||
			strings.Contains(strings.ToLower(mx), "googlemail.com") {
			googleCount++
		}
	}
	if googleCount >= 4 {
		return fmt.Sprintf(
			"Google Workspace now requires only a single MX record (aspmx.l.google.com). "+
				"This domain has %d legacy Google MX records that can be consolidated.",
			googleCount)
	}
	return ""
}

func classifySelectorProvider(selectorName, primaryProvider string) string {
	provider, ok := selectorProviderMap[selectorName]
	if !ok {
		return providerUnknown
	}

	if primaryProvider == providerUnknown && ambiguousSelectors[selectorName] {
		return providerUnknown
	}
	return provider
}

// filterDKIMRecords returns the subset of TXT answers that carry DKIM key
// markers (v=DKIM1 / k= / p=).
func filterDKIMRecords(records []string) []string {
	var dkimRecords []string
	for _, r := range records {
		lower := strings.ToLower(r)
		if strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "k=") || strings.Contains(lower, "p=") {
			dkimRecords = append(dkimRecords, r)
		}
	}
	return dkimRecords
}

func checkDKIMSelector(ctx context.Context, dns interface {
	QueryDNS(ctx context.Context, recordType, domain string) []string
}, selector, domain string) (string, []string) {
	fqdn := fmt.Sprintf("%s.%s", selector, domain)
	records := dns.QueryDNS(ctx, "TXT", fqdn)
	if len(records) == 0 {
		return "", nil
	}
	if dkimRecords := filterDKIMRecords(records); len(dkimRecords) > 0 {
		return selector, dkimRecords
	}
	return "", nil
}

// checkDKIMSelectorWithStatus is the census-path variant of checkDKIMSelector.
// The flat QueryDNS returns an empty slice for BOTH "record absent" and
// "lookup failed", so a scan whose probes transiently failed was
// indistinguishable from one that authoritatively found nothing — flipping the
// verdict (and the posture hash) on a probe that never completed. The third
// result reports that indeterminacy: true means the probe did not complete
// (timeout/SERVFAIL/resolver conflict) and says nothing about the selector.
func (a *Analyzer) checkDKIMSelectorWithStatus(ctx context.Context, selector, domain string) (string, []string, bool) {
	fqdn := fmt.Sprintf("%s.%s", selector, domain)
	records, status := a.resolveWithStatus(ctx, "TXT", fqdn)
	if isIndeterminateLookup(status) {
		return "", nil, true
	}
	if dkimRecords := filterDKIMRecords(records); len(dkimRecords) > 0 {
		return selector, dkimRecords, false
	}
	return "", nil, false
}

// estimateKeyBits infers an RSA key size from the decoded p= byte length when
// the DER itself will not parse. RFC 6376 p= carries a SubjectPublicKeyInfo,
// not a bare modulus, so real keys are modulus + ~34–38 bytes of fixed ASN.1
// framing (measured 2026-08-03 from live captures and openssl-generated keys):
// 1024-bit → 162 bytes, 2048 → 294, 3072 → 422, 4096 → 550. Thresholds sit at
// the midpoints between adjacent real sizes so truncated or nonstandard
// material lands in the nearest bucket. (The previous thresholds — ≤140 →
// 1024 — assumed a bare modulus; every real 1024-bit SPKI is 162 bytes, so
// all real 1024-bit keys were reported as 2048 and the weak-key warning could
// never fire.)
func estimateKeyBits(keyBytes int) int {
	switch {
	case keyBytes <= 228: // (162+294)/2
		return 1024
	case keyBytes <= 358: // (294+422)/2
		return 2048
	case keyBytes <= 486: // (422+550)/2
		return 3072
	case keyBytes <= 700:
		return 4096
	default:
		// Above 4096 bits the ASN.1 framing is a constant 38 bytes
		// (measured: 8192-bit SPKI = 1062 bytes), so bits = (len−38)·8.
		return (keyBytes - 38) * 8
	}
}

// dkimKeyBits measures the key size from the decoded p= material itself
// rather than bucketing its byte length. For k=rsa the material is DER the
// parser can state the modulus of exactly; for k=ed25519 (RFC 8463 §3) it is
// the bare 32-byte public key. The length estimate above is the fallback for
// material that will not parse. isRSA gates the weak-key warning: a bit count
// is only comparable to RFC 8301's RSA thresholds when the key is RSA.
func dkimKeyBits(decoded []byte, keyType string) (bits int, isRSA bool) {
	if pub, err := x509.ParsePKIXPublicKey(decoded); err == nil {
		switch k := pub.(type) {
		case *rsa.PublicKey:
			return k.N.BitLen(), true
		case ed25519.PublicKey:
			return 256, false
		}
	}
	if keyType == "ed25519" {
		if len(decoded) == ed25519.PublicKeySize {
			return 256, false
		}
		// Malformed ed25519 material: no honest bit count exists, and the
		// RSA length estimate would assert one anyway.
		return 0, false
	}
	return estimateKeyBits(len(decoded)), true
}

func analyzePublicKey(record string) (keyBits interface{}, revoked bool, issues []string) {
	m := dkimPKeyRe.FindStringSubmatch(record)
	if m == nil {
		return nil, false, nil
	}
	publicKey := strings.TrimSpace(m[1])
	if publicKey == "" {
		return nil, true, []string{"Key revoked (p= empty)"}
	}
	for len(publicKey)%4 != 0 {
		publicKey += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(publicKey, "="))
		if err != nil {
			return nil, false, nil
		}
	}
	keyType := "rsa"
	if km := dkimKeyTypeRe.FindStringSubmatch(strings.ToLower(record)); km != nil {
		keyType = km[1]
	}
	bits, isRSA := dkimKeyBits(decoded, keyType)
	if bits == 0 {
		return nil, false, nil
	}
	if !isRSA && len(decoded) != ed25519.PublicKeySize {
		// Parsed via x509, so the record carries an SPKI wrapper — but
		// RFC 8463 §3 defines p= as the bare 32-octet key, and strict
		// verifiers reject the wrapped form even though the key inside
		// is sound. The bit count stays honest; the interop break is
		// the finding.
		issues = append(issues, "Ed25519 key is SPKI-wrapped; RFC 8463 requires the bare 32-byte public key, so strict verifiers will treat this record as invalid")
	}
	if isRSA && bits < 2048 {
		issues = append(issues, fmt.Sprintf("%d-bit key (weak, upgrade to 2048)", bits))
	}
	return bits, false, issues
}

func analyzeDKIMKey(record string) map[string]any {
	// Same key, same analysis, regardless of how the transport rejoined the
	// 255-byte TXT chunks: the raw form can carry chunk-boundary spaces or
	// character-string quotes mid-base64, which the tag regexes would read as
	// value terminators — truncating p= and misclassifying the key.
	record = canonicalDKIMRecord(record)
	keyInfo := map[string]any{
		"key_type":    "rsa",
		mapKeyKeyBits: nil,
		mapKeyRevoked: false,
		"test_mode":   false,
		mapKeyIssues:  []string{},
	}

	keyType := "rsa"
	if m := dkimKeyTypeRe.FindStringSubmatch(strings.ToLower(record)); m != nil {
		keyType = m[1]
		keyInfo["key_type"] = keyType
	}

	lower := strings.ToLower(record)
	testMode := dkimTestFlagRe.MatchString(lower)
	keyInfo["test_mode"] = testMode

	keyBits, revoked, pkIssues := analyzePublicKey(record)
	keyInfo[mapKeyKeyBits] = keyBits
	keyInfo[mapKeyRevoked] = revoked

	if keyBits != nil {
		if bits, ok := keyBits.(int); ok {
			c := ClassifyDKIMKey(keyType, bits)
			keyInfo["key_strength"] = c.Strength
			keyInfo["key_strength_label"] = c.Label
			keyInfo["key_strength_rfc"] = c.RFC
			keyInfo["key_strength_observation"] = c.Observation
		}
	}

	var issues []string
	issues = append(issues, pkIssues...)

	if testMode {
		issues = append(issues, "DKIM key in test mode (t=y per RFC 6376 §3.6.1) — verifiers should treat failures as unsigned, remove t=y for production")
	}

	if issues == nil {
		issues = []string{}
	}
	keyInfo[mapKeyIssues] = issues
	return keyInfo
}

func AllSelectorsKnown(customSelectors []string) bool {
	if len(customSelectors) == 0 {
		return true
	}
	known := make(map[string]bool, len(defaultDKIMSelectors))
	for _, s := range defaultDKIMSelectors {
		known[s] = true
	}
	for _, cs := range customSelectors {
		cs = strings.TrimSpace(strings.ToLower(cs))
		cs = strings.TrimRight(cs, ".")
		if cs == "" {
			continue
		}
		if !strings.HasSuffix(cs, domainkeySuffix) {
			cs = cs + domainkeySuffix
		}
		if !known[cs] {
			return false
		}
	}
	return true
}

func buildSelectorList(customSelectors []string) []string {
	selectors := make([]string, 0, len(defaultDKIMSelectors)+len(customSelectors))
	if len(customSelectors) > 0 {
		for _, cs := range customSelectors {
			if !strings.HasSuffix(cs, domainkeySuffix) {
				cs = cs + domainkeySuffix
			}
			selectors = append(selectors, cs)
		}
	}
	for _, s := range defaultDKIMSelectors {
		found := false
		for _, existing := range selectors {
			if existing == s {
				found = true
				break
			}
		}
		if !found {
			selectors = append(selectors, s)
		}
	}
	return selectors
}

func findSPFRecord(records []string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
			return r
		}
	}
	return ""
}

func collectUnattributed(foundSelectors map[string]map[string]any) []string {
	var unattributed []string
	for selName, selData := range foundSelectors {
		if selData[mapKeyProvider].(string) == providerUnknown {
			unattributed = append(unattributed, selName)
		}
	}
	return unattributed
}

func checkPrimaryHasDKIM(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) bool {
	expected := primaryProviderSelectors[primaryProvider]
	if len(expected) > 0 {
		for _, s := range expected {
			if _, ok := foundSelectors[s]; ok {
				return true
			}
		}
		return false
	}
	return foundProviders[primaryProvider]
}

func inferUnattributedSelectors(foundSelectors map[string]map[string]any, unattributed []string, primaryProvider string, foundProviders map[string]bool) string {
	for _, selName := range unattributed {
		foundSelectors[selName][mapKeyProvider] = primaryProvider
		foundSelectors[selName]["inferred"] = true
		foundProviders[primaryProvider] = true
	}
	var names []string
	for _, s := range unattributed {
		names = append(names, strings.TrimSuffix(s, domainkeySuffix))
	}
	return fmt.Sprintf(
		"DKIM selector(s) %s inferred as %s (custom selector names — not the standard %s selector).",
		strings.Join(names, ", "), primaryProvider, primaryProvider,
	)
}

func buildThirdPartyNote(foundProviders map[string]bool, primaryProvider string) string {
	var providerNames []string
	for p := range foundProviders {
		providerNames = append(providerNames, p)
	}
	sort.Strings(providerNames)
	thirdPartyNames := "third-party services"
	if len(providerNames) > 0 {
		thirdPartyNames = strings.Join(providerNames, ", ")
	}
	return fmt.Sprintf(
		"DKIM verified for %s only — no DKIM found for primary mail platform (%s). "+
			"The primary provider may use custom selectors not discoverable through standard checks. "+
			"Try re-scanning with a custom DKIM selector if you know yours.",
		thirdPartyNames, primaryProvider,
	)
}

func attributeSelectors(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) (bool, string, bool) {
	if primaryProvider == providerUnknown {
		return false, "", false
	}

	unattributed := collectUnattributed(foundSelectors)
	primaryHasDKIM := checkPrimaryHasDKIM(foundSelectors, primaryProvider, foundProviders)

	if !primaryHasDKIM && len(unattributed) > 0 {
		note := inferUnattributedSelectors(foundSelectors, unattributed, primaryProvider, foundProviders)
		return true, note, false
	}

	if len(foundSelectors) > 0 && !primaryHasDKIM {
		return false, buildThirdPartyNote(foundProviders, primaryProvider), true
	}

	return primaryHasDKIM, "", false
}

func buildDKIMVerdict(foundSelectors map[string]map[string]any, keyIssues, keyStrengths []string, primaryProvider string, primaryHasDKIM, thirdPartyOnly bool) (string, string) {
	if len(foundSelectors) == 0 {
		return "info", "DKIM not discoverable via common selectors (large providers use rotating selectors)"
	}

	hasWeakKey := false
	hasRevoked := false
	for _, issue := range keyIssues {
		// Weak keys are no longer always exactly 1024-bit: exact DER parsing
		// can measure 512/768/1536 etc., so match the marker every weak-key
		// issue carries, not one bit count.
		if strings.Contains(issue, "1024-bit") || strings.Contains(issue, "(weak") {
			hasWeakKey = true
		}
		if strings.Contains(issue, mapKeyRevoked) {
			hasRevoked = true
		}
	}

	uniqueStrengths := uniqueStrings(keyStrengths)

	if hasRevoked {
		return "warning", fmt.Sprintf("Found %d DKIM selector(s) but some keys are revoked", len(foundSelectors))
	}
	if hasWeakKey {
		return "warning", fmt.Sprintf("Found %d DKIM selector(s) with weak key(s) (below 2048-bit RSA)", len(foundSelectors))
	}
	if thirdPartyOnly {
		if len(uniqueStrengths) > 0 {
			return "partial", fmt.Sprintf("Found DKIM for %d selector(s) (%s) but none for primary mail platform (%s)",
				len(foundSelectors), strings.Join(uniqueStrengths, ", "), primaryProvider)
		}
		return "partial", fmt.Sprintf("Found DKIM for %d selector(s) but none for primary mail platform (%s)",
			len(foundSelectors), primaryProvider)
	}

	if len(uniqueStrengths) > 0 {
		return "success", fmt.Sprintf("Found DKIM for %d selector(s) with strong keys (%s)",
			len(foundSelectors), strings.Join(uniqueStrengths, ", "))
	}
	return "success", fmt.Sprintf("Found DKIM records for %d selector(s)", len(foundSelectors))
}

// dkimWildcardProbe is a selector no provider uses. If it resolves, the zone
// publishes a wildcard *._domainkey record, so every selector "found" during
// the scan is a wildcard artifact rather than a provider-specific key.
const dkimWildcardProbe = "dnstool-wildcard-probe" + domainkeySuffix

// allDKIMKeysRevoked reports whether every discovered key across every
// selector is revoked (empty p= tag, RFC 6376 §3.6.1). Selectors without
// key_info are indeterminate and therefore never counted as revoked.
func allDKIMKeysRevoked(foundSelectors map[string]map[string]any) bool {
	if len(foundSelectors) == 0 {
		return false
	}
	for _, selData := range foundSelectors {
		keys := extractKeyInfoList(selData["key_info"])
		if len(keys) == 0 {
			return false
		}
		for _, ki := range keys {
			revoked, _ := ki[mapKeyRevoked].(bool)
			if !revoked {
				return false
			}
		}
	}
	return true
}

// extractKeyInfoList tolerates both the live []map[string]any shape and the
// JSON round-trip []any shape.
func extractKeyInfoList(v any) []map[string]any {
	switch list := v.(type) {
	case []map[string]any:
		return list
	case []any:
		out := make([]map[string]any, 0, len(list))
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// hasNullMXRecords reports whether the MX record set includes a null MX
// (RFC 7505: exchange of "."), the explicit declaration that a domain
// accepts no mail.
func hasNullMXRecords(mxRecords []string) bool {
	for _, mx := range mxRecords {
		fields := strings.Fields(mx)
		if len(fields) == 0 {
			continue
		}
		if fields[len(fields)-1] == "." {
			return true
		}
	}
	return false
}

// isSPFHardFailOnly reports whether the SPF record is exactly "v=spf1 -all" —
// the bare hard-fail form that declares the domain sends no mail (RFC 7208
// §8.4 fail qualifier with no authorized senders).
func isSPFHardFailOnly(spfRecord string) bool {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(spfRecord)))
	return len(fields) == 2 && fields[0] == "v=spf1" && fields[1] == "-all"
}

// applyDKIMLockdownVerdict upgrades or sharpens the DKIM verdict when every
// discovered key is revoked. A revoked key (v=DKIM1; p=) on a no-mail domain
// is the RFC 6376 §3.6.1 declaration that the domain signs nothing —
// best-practice lockdown, not a misconfiguration. On a mail-sending domain
// the same signal is a genuine problem.
func applyDKIMLockdownVerdict(status, message string, allRevoked, wildcard, noMail bool, selectorCount int) (string, string) {
	if !allRevoked {
		return status, message
	}
	if noMail {
		if wildcard {
			return "success", "DKIM locked down: a wildcard revoked key (v=DKIM1; p=) answers every selector — RFC 6376 §3.6.1 declares all signing keys revoked. Best practice for a domain that sends no mail."
		}
		return "success", fmt.Sprintf("DKIM locked down: all %d published key(s) are revoked (v=DKIM1; p=) per RFC 6376 §3.6.1 — consistent with this domain's no-mail declaration.", selectorCount)
	}
	if wildcard {
		return "warning", "A wildcard revoked DKIM key (v=DKIM1; p=, RFC 6376 §3.6.1) answers every selector — outbound mail cannot be DKIM-verified. If this domain sends no mail, add a null MX (RFC 7505) and SPF \"v=spf1 -all\" to complete the lockdown."
	}
	return "warning", fmt.Sprintf("All %d discovered DKIM key(s) are revoked (v=DKIM1; p=, RFC 6376 §3.6.1) — outbound mail cannot be DKIM-verified.", selectorCount)
}

func isCustomSelector(selectorName string, customSelectors []string) bool {
	for _, cs := range customSelectors {
		csNorm := cs
		if !strings.HasSuffix(csNorm, domainkeySuffix) {
			csNorm = csNorm + domainkeySuffix
		}
		if csNorm == selectorName {
			return true
		}
	}
	return false
}

func analyzeRecordKeys(records []string) ([]map[string]any, []string, []string) {
	var keyInfoList []map[string]any
	var issues []string
	var strengths []string
	for _, rec := range records {
		ka := analyzeDKIMKey(rec)
		keyInfoList = append(keyInfoList, ka)
		issues = append(issues, ka[mapKeyIssues].([]string)...)
		if bits, ok := ka[mapKeyKeyBits]; ok && bits != nil {
			if b, ok := bits.(int); ok && b >= 2048 {
				strengths = append(strengths, fmt.Sprintf("%d-bit", b))
			}
		}
	}
	return keyInfoList, issues, strengths
}

type dkimScanResult struct {
	selectorName string
	selectorInfo map[string]any
	keyIssues    []string
	keyStrengths []string
}

// processDKIMSelector probes one selector for the census. The bool reports an
// indeterminate probe (see checkDKIMSelectorWithStatus) — nil result plus true
// means "could not tell", never "absent".
func (a *Analyzer) processDKIMSelector(ctx context.Context, sel, domain, primaryProvider string, customSelectors []string) (*dkimScanResult, bool) {
	selectorName, records, indeterminate := a.checkDKIMSelectorWithStatus(ctx, sel, domain)
	if selectorName == "" {
		return nil, indeterminate
	}

	provider := classifySelectorProvider(selectorName, primaryProvider)
	keyInfoList, localIssues, localStrengths := analyzeRecordKeys(records)

	selectorInfo := map[string]any{
		"records":      records,
		"key_info":     keyInfoList,
		mapKeyProvider: provider,
		"user_hint":    isCustomSelector(selectorName, customSelectors),
	}

	return &dkimScanResult{
		selectorName: selectorName,
		selectorInfo: selectorInfo,
		keyIssues:    localIssues,
		keyStrengths: localStrengths,
	}, false
}

func collectFoundProviders(foundSelectors map[string]map[string]any) map[string]bool {
	providers := make(map[string]bool)
	for _, selData := range foundSelectors {
		p := selData[mapKeyProvider].(string)
		if p != providerUnknown {
			providers[p] = true
		}
	}
	return providers
}

func inferMailboxBehindGateway(res *ProviderResolution, foundProviders map[string]bool) {
	if !securityGateways[res.Primary] {
		return
	}

	var mailboxCandidates []string
	for p := range foundProviders {
		if mailboxProviders[p] {
			mailboxCandidates = append(mailboxCandidates, p)
		}
	}

	if len(mailboxCandidates) == 1 {
		inferred := mailboxCandidates[0]
		res.DKIMInferenceNote = fmt.Sprintf(
			"Primary mailbox provider inferred as %s from DKIM selectors (mail routed through %s security gateway).",
			inferred, res.Primary,
		)
		res.Gateway = res.Primary
		res.Primary = inferred
		return
	}

	if len(mailboxCandidates) > 1 {
		sort.Strings(mailboxCandidates)
		res.DKIMInferenceNote = fmt.Sprintf(
			"Multiple mailbox providers detected behind %s gateway (%s) — cannot determine single primary from DKIM alone.",
			res.Primary, strings.Join(mailboxCandidates, ", "),
		)
	}
}

func reclassifyAmbiguousSelectors(foundSelectors map[string]map[string]any, finalPrimary string) {
	for selName, selData := range foundSelectors {
		if selData[mapKeyProvider].(string) != providerUnknown {
			continue
		}
		if !ambiguousSelectors[selName] {
			continue
		}
		if mapped, ok := selectorProviderMap[selName]; ok && finalPrimary != providerUnknown {
			selData[mapKeyProvider] = mapped
			selData["reclassified"] = true
		}
	}
}

var dkimNSProviders = map[string]string{
	"ondmarc.com":    "Red Sift OnDMARC",
	"easydmarc.com":  "EasyDMARC",
	"valimail.com":   "Valimail",
	"dmarcian.com":   "dmarcian",
	"powerdmarc.com": "PowerDMARC",
	"agari.com":      "Agari (Fortra)",
	"socketlabs.com": "SocketLabs",
	"proofpoint.com": "Proofpoint",
	"mimecast.com":   "Mimecast",
}

type DKIMDelegation struct {
	Detected    bool
	Nameservers []string
	Provider    string
}

func matchDKIMNSProvider(nameservers []string) string {
	for _, ns := range nameservers {
		for suffix, name := range dkimNSProviders {
			if strings.HasSuffix(ns, suffix) {
				return name
			}
		}
	}
	return ""
}

func normalizeDKIMNS(nsRecords []string) []string {
	var nameservers []string
	for _, ns := range nsRecords {
		normalized := strings.ToLower(strings.TrimRight(ns, "."))
		if normalized != "" {
			nameservers = append(nameservers, normalized)
		}
	}
	return nameservers
}

func (a *Analyzer) detectDKIMDelegation(ctx context.Context, domain string) DKIMDelegation {
	dkZone := "_domainkey." + domain
	nsRecords := a.DNS.QueryDNS(ctx, "NS", dkZone)
	if len(nsRecords) == 0 {
		return DKIMDelegation{}
	}

	nameservers := normalizeDKIMNS(nsRecords)
	if len(nameservers) == 0 {
		return DKIMDelegation{}
	}

	return DKIMDelegation{
		Detected:    true,
		Nameservers: nameservers,
		Provider:    matchDKIMNSProvider(nameservers),
	}
}

// detectDKIMWildcardLockdown reports whether every found selector carries a
// revoked (empty-p) key and, if so, probes a nonce selector to detect a
// wildcard *._domainkey record answering every query. Returns
// (allRevoked, wildcardDKIM, wildcardRecords).
func detectDKIMWildcardLockdown(probeName string, probeRecords []string, foundSelectors map[string]map[string]any) (bool, bool, []string) {
	if !allDKIMKeysRevoked(foundSelectors) {
		return false, false, nil
	}
	if probeName != "" {
		return true, true, probeRecords
	}
	return true, false, nil
}

// buildDKIMSelectorMap converts foundSelectors into the exported selectors
// map. Under a wildcard lockdown the zone holds ONE wildcard record that
// answers every selector probe — persisting each probed name as a "found"
// selector with provider attribution would fabricate infrastructure that was
// never configured (Zero Fabrication Rule), so it collapses to the single
// record the zone publishes.
func buildDKIMSelectorMap(foundSelectors map[string]map[string]any, lockdownCollapse bool, wildcardRecords []string) map[string]any {
	selectorMap := make(map[string]any, len(foundSelectors))
	if lockdownCollapse {
		wildcardKeyInfo, _, _ := analyzeRecordKeys(wildcardRecords)
		selectorMap["*._domainkey"] = map[string]any{
			"records":      wildcardRecords,
			"key_info":     wildcardKeyInfo,
			mapKeyProvider: "",
			"user_hint":    false,
			"wildcard":     true,
		}
		return selectorMap
	}
	for k, v := range foundSelectors {
		selectorMap[k] = v
	}
	return selectorMap
}

// dkimCensusState returns the selector-census tri-state, mirroring
// spf_state/dmarc_state/dnssec_state: drift may only compare two selector
// censuses when both are authoritative. Indeterminate outranks present
// because even one incomplete probe can hide a selector the previous scan
// found — an incomplete census can neither confirm the selector set nor
// confirm absence. Absence is only absent_confirmed when every probe
// authoritatively answered. When the census is both incomplete and empty,
// the returned message replaces the caller's: "not discoverable" is a
// claim about probes that completed, and when they did not, we say so
// instead of implying the selectors were checked and found empty
// (RFC 7208 §4.6 / RFC 7489 §6.6.3 logic applied to selector discovery).
func dkimCensusState(found, indeterminate, probed int, message string) (string, string) {
	switch {
	case indeterminate > 0 && found == 0:
		return triStateIndeterminate, fmt.Sprintf(
			"DKIM could not be verified: %d of %d selector probes did not complete (transient SERVFAIL/timeout/network error). This is not evidence that DKIM is absent — re-run before concluding it is unconfigured.",
			indeterminate, probed)
	case indeterminate > 0:
		return triStateIndeterminate, message
	case found > 0:
		return triStatePresent, message
	}
	return triStateAbsentConf, message
}

func (a *Analyzer) AnalyzeDKIM(ctx context.Context, domain string, mxRecords, customSelectors []string) map[string]any {
	selectors := buildSelectorList(customSelectors)

	if len(mxRecords) == 0 {
		mxRecords = a.DNS.QueryDNS(ctx, "MX", domain)
	}

	dkimDelegation := a.detectDKIMDelegation(ctx, domain)

	spfRecord := findSPFRecord(a.DNS.QueryDNS(ctx, "TXT", domain))

	res := detectPrimaryMailProvider(mxRecords, spfRecord)

	foundSelectors := make(map[string]map[string]any)
	var keyIssues []string
	var keyStrengths []string
	var indeterminateProbes int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// The wildcard probe runs WITH the census, never after it: on a
	// wildcard zone every census name answers — slowly, with CD fallbacks
	// on bogus zones — and a probe sequenced after wg.Wait() pays its
	// round-trip from an exhausted budget. The detector was starved by the
	// thing it detects (measured on the evil fixture 2026-08-16: 81/81
	// census answers, probe dead, wildcard_dkim false while the zone
	// wildcards live).
	var wildcardProbeName string
	var wildcardProbeRecords []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, r := checkDKIMSelector(ctx, a.DNS, dkimWildcardProbe, domain)
		mu.Lock()
		wildcardProbeName, wildcardProbeRecords = n, r
		mu.Unlock()
	}()
	for _, sel := range selectors {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			result, indeterminate := a.processDKIMSelector(ctx, s, domain, res.Primary, customSelectors)
			mu.Lock()
			defer mu.Unlock()
			if indeterminate {
				indeterminateProbes++
			}
			if result == nil {
				return
			}
			foundSelectors[result.selectorName] = result.selectorInfo
			keyIssues = append(keyIssues, result.keyIssues...)
			keyStrengths = append(keyStrengths, result.keyStrengths...)
		}(sel)
	}
	wg.Wait()

	foundProviders := collectFoundProviders(foundSelectors)

	prePrimary := res.Primary
	inferMailboxBehindGateway(&res, foundProviders)

	if res.Primary != prePrimary {
		reclassifyAmbiguousSelectors(foundSelectors, res.Primary)
		foundProviders = collectFoundProviders(foundSelectors)
	}

	primaryHasDKIM, primaryDKIMNote, thirdPartyOnly := attributeSelectors(foundSelectors, res.Primary, foundProviders)
	if res.DKIMInferenceNote != "" && primaryDKIMNote == "" {
		primaryDKIMNote = res.DKIMInferenceNote
	} else if res.DKIMInferenceNote != "" {
		primaryDKIMNote = res.DKIMInferenceNote + " " + primaryDKIMNote
	}

	status, message := buildDKIMVerdict(foundSelectors, keyIssues, keyStrengths, res.Primary, primaryHasDKIM, thirdPartyOnly)

	allRevoked, wildcardDKIM, wildcardRecords := detectDKIMWildcardLockdown(wildcardProbeName, wildcardProbeRecords, foundSelectors)
	lockdownCollapse := wildcardDKIM && allRevoked
	noMail := hasNullMXRecords(mxRecords) || isSPFHardFailOnly(spfRecord)
	status, message = applyDKIMLockdownVerdict(status, message, allRevoked, wildcardDKIM, noMail, len(foundSelectors))
	if allRevoked {
		// One revocation signal repeated per selector is noise —
		// collapse to the unique issue set.
		keyIssues = uniqueStrings(keyIssues)
	}
	if lockdownCollapse {
		// Every selector hit is a wildcard artifact — the per-provider
		// attribution is phantom, so suppress it rather than report
		// providers that were never configured.
		foundProviders = map[string]bool{}
	}

	dkimState, message := dkimCensusState(len(foundSelectors), indeterminateProbes, len(selectors), message)

	var sortedProviders []string
	for p := range foundProviders {
		sortedProviders = append(sortedProviders, p)
	}
	sort.Strings(sortedProviders)

	selectorMap := buildDKIMSelectorMap(foundSelectors, lockdownCollapse, wildcardRecords)

	var delegationMap map[string]any
	if dkimDelegation.Detected {
		delegationMap = map[string]any{
			"detected":     true,
			"nameservers":  dkimDelegation.Nameservers,
			mapKeyProvider: dkimDelegation.Provider,
		}
	}

	// DKIM provenance: the actual number of selectors probed, and whether any
	// were user-supplied. This changes the evidentiary weight of the result —
	// "inconclusive against N defaults" and "verified via a user-supplied
	// selector" are different claims (mint contract §5).
	selectorSource := "defaults_only"
	if len(customSelectors) > 0 {
		if AllSelectorsKnown(customSelectors) {
			selectorSource = "mixed"
		} else {
			selectorSource = "user_supplied"
		}
	}

	return map[string]any{
		"status":               status,
		"message":              message,
		mapKeyDkimState:        dkimState,
		"selectors":            selectorMap,
		"probe_scope":          len(selectors),
		"selector_source":      selectorSource,
		"key_issues":           keyIssues,
		"key_strengths":        uniqueStrings(keyStrengths),
		"primary_provider":     res.Primary,
		"security_gateway":     res.GatewayOrNil(),
		"primary_has_dkim":     primaryHasDKIM,
		"third_party_only":     thirdPartyOnly,
		"primary_dkim_note":    primaryDKIMNote,
		"found_providers":      sortedProviders,
		"wildcard_dkim":        wildcardDKIM,
		"all_revoked":          allRevoked,
		"spf_ancillary_note":   res.SPFAncillaryNote,
		"mx_legacy_note":       res.MXLegacyNote,
		"domainkey_delegation": delegationMap,
	}
}
