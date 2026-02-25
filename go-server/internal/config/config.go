// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package config

import (
        "fmt"
        "os"
        "strings"
)

var (
        Version   = "26.25.86"
        GitCommit = "dev"
        BuildTime = "unknown"
)

type ProbeEndpoint struct {
        ID    string
        Label string
        URL   string
        Key   string
}

type Config struct {
        DatabaseURL        string
        SessionSecret      string
        Port               string
        AppVersion         string
        Testing            bool
        SMTPProbeMode      string
        ProbeAPIURL        string
        ProbeAPIKey        string
        Probes             []ProbeEndpoint
        MaintenanceNote    string
        SectionTuning      map[string]string
        BetaPages          map[string]bool
        GoogleClientID     string
        GoogleClientSecret string
        GoogleRedirectURL  string
        InitialAdminEmail  string
        BaseURL            string
        IsDevEnvironment   bool
        DiscordWebhookURL  string
}

var betaPagesMap = map[string]bool{
        "toolkit":      true,
        "investigate":  true,
        "email-header": true,
        "ttl-tuner":    true,
}

var sectionTuningMap = map[string]string{
        // "email": "Accuracy Tuning",
        // "dane":         "Accuracy Tuning",
        // "brand": "Accuracy Tuning",
        // "securitytxt":  "Accuracy Tuning",
        "ai": "Beta",
        // "secrets":      "Accuracy Tuning",
        // "web-exposure": "Accuracy Tuning",
        "smtp": "Beta",
        // "infra": "Accuracy Tuning",
        // "dnssec":       "Accuracy Tuning",
        // "traffic":      "Accuracy Tuning",
}

func Load() (*Config, error) {
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                return nil, fmt.Errorf("DATABASE_URL environment variable is required")
        }

        sessionSecret := os.Getenv("SESSION_SECRET")
        if sessionSecret == "" {
                return nil, fmt.Errorf("SESSION_SECRET environment variable is required")
        }

        port := os.Getenv("PORT")
        if port == "" {
                port = "5000"
        }

        smtpProbeMode := os.Getenv("SMTP_PROBE_MODE")
        if smtpProbeMode == "" {
                smtpProbeMode = "skip"
        }

        probeAPIURL := os.Getenv("PROBE_API_URL")
        if probeAPIURL != "" && smtpProbeMode == "skip" {
                smtpProbeMode = "remote"
        }

        var probes []ProbeEndpoint
        if probeAPIURL != "" {
                label := os.Getenv("PROBE_LABEL")
                if label == "" {
                        label = "US-East (Boston)"
                }
                probes = append(probes, ProbeEndpoint{
                        ID:    "probe-01",
                        Label: label,
                        URL:   probeAPIURL,
                        Key:   os.Getenv("PROBE_API_KEY"),
                })
        }
        probeAPIURL2 := os.Getenv("PROBE_API_URL_2")
        if probeAPIURL2 != "" {
                label2 := os.Getenv("PROBE_LABEL_2")
                if label2 == "" {
                        label2 = "EU-West (France)"
                }
                probes = append(probes, ProbeEndpoint{
                        ID:    "probe-02",
                        Label: label2,
                        URL:   probeAPIURL2,
                        Key:   os.Getenv("PROBE_API_KEY_2"),
                })
        }

        maintenanceNote := os.Getenv("MAINTENANCE_NOTE")

        tuning := make(map[string]string)
        for k, v := range sectionTuningMap {
                tuning[k] = v
        }
        envTuning := os.Getenv("SECTION_TUNING")
        if envTuning != "" {
                for _, pair := range strings.Split(envTuning, ",") {
                        parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
                        if len(parts) == 2 {
                                tuning[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
                        }
                }
        }

        baseURLRaw := os.Getenv("BASE_URL")
        baseURL := baseURLRaw
        if baseURL == "" {
                baseURL = "https://dnstool.it-help.tech"
        }
        isDevEnv := baseURLRaw == "" || baseURL != "https://dnstool.it-help.tech"

        googleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
        if googleRedirectURL == "" {
                googleRedirectURL = baseURL + "/auth/callback"
        }

        betaPages := make(map[string]bool)
        for k, v := range betaPagesMap {
                betaPages[k] = v
        }

        return &Config{
                DatabaseURL:        dbURL,
                SessionSecret:      sessionSecret,
                Port:               port,
                AppVersion:         Version,
                Testing:            false,
                SMTPProbeMode:      smtpProbeMode,
                ProbeAPIURL:        probeAPIURL,
                ProbeAPIKey:        os.Getenv("PROBE_API_KEY"),
                Probes:             probes,
                MaintenanceNote:    maintenanceNote,
                SectionTuning:      tuning,
                BetaPages:          betaPages,
                GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
                GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
                GoogleRedirectURL:  googleRedirectURL,
                InitialAdminEmail:  strings.TrimSpace(os.Getenv("INITIAL_ADMIN_EMAIL")),
                BaseURL:            baseURL,
                IsDevEnvironment:   isDevEnv,
                DiscordWebhookURL:  os.Getenv("DISCORD_WEBHOOK_URL"),
        }, nil
}
