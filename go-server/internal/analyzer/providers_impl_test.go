package analyzer

import (
        "testing"
)

func TestDmarcMonitoringProviders_Initialized(t *testing.T) {
        if dmarcMonitoringProviders == nil {
                t.Error("dmarcMonitoringProviders should not be nil ")
        }
}

func TestSpfFlatteningProviders_Initialized(t *testing.T) {
        if spfFlatteningProviders == nil {
                t.Error("spfFlatteningProviders should not be nil ")
        }
}

func TestHostedDKIMProviders_Initialized(t *testing.T) {
        if hostedDKIMProviders == nil {
                t.Error("hostedDKIMProviders should not be nil ")
        }
}

func TestDynamicServicesProviders_Initialized(t *testing.T) {
        if dynamicServicesProviders == nil {
                t.Error("dynamicServicesProviders should not be nil ")
        }
}

func TestDynamicServicesZones_Initialized(t *testing.T) {
        if dynamicServicesZones == nil {
                t.Error("dynamicServicesZones should not be nil ")
        }
}

func TestCnameProviderMap_Initialized(t *testing.T) {
        if cnameProviderMap == nil {
                t.Error("cnameProviderMap should not be nil ")
        }
}

func TestProviderConstants_NonEmpty(t *testing.T) {
        constants := map[string]string{
                "nameOnDMARC":       nameOnDMARC,
                "nameDMARCReport":   nameDMARCReport,
                "nameDMARCLY":       nameDMARCLY,
                "nameDmarcian":      nameDmarcian,
                "nameSendmarc":      nameSendmarc,
                "nameProofpoint":    nameProofpoint,
                "nameValimailEnf":   nameValimailEnf,
                "nameProofpointEFD": nameProofpointEFD,
                "namePowerDMARC":    namePowerDMARC,
                "nameMailhardener":  nameMailhardener,
                "nameFraudmarc":     nameFraudmarc,
                "nameEasyDMARC":     nameEasyDMARC,
                "nameDMARCAdvisor":  nameDMARCAdvisor,
                "nameRedSift":       nameRedSift,
        }
        for name, val := range constants {
                if val == "" {
                        t.Errorf("constant %s is empty", name)
                }
        }
}

func TestVendorConstants_NonEmpty(t *testing.T) {
        vendors := map[string]string{
                "vendorRedSift":    vendorRedSift,
                "vendorValimail":   vendorValimail,
                "vendorDmarcian":   vendorDmarcian,
                "vendorSendmarc":   vendorSendmarc,
                "vendorProofpoint": vendorProofpoint,
                "vendorDMARCLY":    vendorDMARCLY,
                "vendorPowerDMARC": vendorPowerDMARC,
                "vendorFraudmarc":  vendorFraudmarc,
                "vendorEasyDMARC":  vendorEasyDMARC,
        }
        for name, val := range vendors {
                if val == "" {
                        t.Errorf("vendor constant %s is empty", name)
                }
        }
}

func TestDomainConstants_NonEmpty(t *testing.T) {
        domains := []string{domainOndmarc, domainRedsift, domainDmarcian, domainSendmarc}
        for _, d := range domains {
                if d == "" {
                        t.Error("domain constant is empty")
                }
        }
}
