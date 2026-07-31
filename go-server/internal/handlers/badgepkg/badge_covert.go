// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package badgepkg

import (
        "strings"
        "fmt"
        "time"
        "strconv"
)

type CovertLine struct {
        Prefix      string
        Text        string
        Color       string
        PrefixColor string
        Desc        string
        DescColor   string
        Link        string
}

type CovertDesc struct {
        Success string
        Warning string
        Fail    string
}

type CovertRenderCtx struct {
        XPad          int
        LineH         int
        FontSize      int
        CharW         int
        Width         int
        MonoFont      string
        DimLocked     string
        SRed          string
        Alt           string
        ResultStartAt float64
}

var CovertDescriptions = map[string]CovertDesc{
        "SPF":       {Success: "can't forge sender envelope", Warning: "partial — spoofing harder", Fail: "sender spoofing possible"},
        "DKIM":      {Success: "can't forge signatures", Warning: "weak key — forgery harder", Fail: "message forgery possible"},
        protoDMARC:  {Success: "spoofing rejected at gate", Warning: "monitoring only — not blocking", Fail: "email spoofing wide open"},
        protoDNSSEC: {Success: "can't poison DNS cache", Warning: "partial — some zones exposed", Fail: "DNS cache poisoning possible"},
        "DANE":      {Success: "can't downgrade TLS", Warning: "TLSA present but weak", Fail: "TLS downgrade possible"},
        protoMTASTS: {Success: "can't intercept mail", Warning: "testing mode — not enforcing", Fail: "mail interception possible"},
        protoTLSRPT: {Success: "transport monitored", Warning: "partial reporting", Fail: "no transport monitoring"},
        "BIMI":      {Success: "brand verification active", Warning: "present but no VMC cert", Fail: "brand impersonation possible"},
        "CAA":       {Success: "cert issuance locked", Warning: "policy present but weak", Fail: "anyone can issue certs"},
        "Web3":      {Success: "Web3 infra detected", Warning: "partial Web3 presence", Fail: "no Web3 detected"},
}

func CovertStatusPrefix(status string) string {
        switch status {
        case "success":
                return "[+]"
        case "warning":
                return "[~]"
        default:
                return "[-]"
        }
}

func CovertProtocolLine(abbrev, status string) CovertLine {
        pad := 10 - len(abbrev)
        if pad < 1 {
                pad = 1
        }
        dots := strings.Repeat(".", pad)
        label := abbrev + " " + dots + " "

        desc, ok := CovertDescriptions[abbrev]
        if !ok {
                return CovertLine{Prefix: "[?]", Text: label, Color: hexScRed, Desc: "unknown", DescColor: hexScRed}
        }

        msg := desc.Fail
        switch status {
        case "success":
                msg = desc.Success
        case "warning":
                msg = desc.Warning
        }

        return CovertLine{Prefix: CovertStatusPrefix(status), Text: label, Color: hexScRed, Desc: msg, DescColor: hexScRed}
}

func CovertExposureLines(exposure ExposureData, sRed, alt, baseURL string, scanID int32) []CovertLine {
        if exposure.Status != "exposed" || exposure.FindingCount == 0 {
                return nil
        }
        cl := func(pfx, txt, c string) CovertLine {
                return CovertLine{Prefix: pfx, Text: txt, Color: c}
        }
        var lines []CovertLine
        lines = append(lines, cl("", "", ""))
        lines = append(lines, cl("", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", alt))
        lines = append(lines, cl("[!!]", fmt.Sprintf("SECRET EXPOSURE — %d credential%s found", exposure.FindingCount, PluralS(exposure.FindingCount)), sRed))
        lines = append(lines, cl("", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", alt))
        for _, f := range exposure.Findings {
                label := f.FindingType
                if label == "" {
                        label = "Secret"
                }
                redacted := f.Redacted
                if len(redacted) > 24 {
                        redacted = redacted[:21] + "..."
                }
                sevTag := CovertSeverityTag(f.Severity)
                findingLine := cl("[!!]", fmt.Sprintf("  >>> %s: %s%s", label, redacted, sevTag), alt)
                findingLine.Link = fmt.Sprintf("%s/analysis/%d/view/C#secret-exposure", baseURL, scanID)
                lines = append(lines, findingLine)
        }
        lines = append(lines, cl("[!!]", "  Credentials are publicly accessible.", sRed))
        return lines
}

func CovertSeverityTag(severity string) string {
        switch severity {
        case "critical":
                return " [CRITICAL]"
        case "high":
                return " [HIGH]"
        default:
                return ""
        }
}

func CovertPrefixColor(prefix, dimLocked, sRed, alt string) string {
        switch prefix {
        case "[+]":
                return dimLocked
        case "[~]":
                return "#8a8a00"
        case "[-]":
                return "#7a2419"
        case "[!!]", "[!]":
                return sRed
        default:
                return alt
        }
}

type CovertSummaryParams struct {
        Vulnerable, FindingCount int
        Tagline                  string
        Locked, DimLocked        string
        SRed, Alt                string
}

func CovertSummaryLines(p CovertSummaryParams) []CovertLine {
        cl := func(pfx, txt, c string) CovertLine {
                return CovertLine{Prefix: pfx, Text: txt, Color: c}
        }
        checkCount := 10
        if p.Vulnerable == 0 && p.FindingCount == 0 {
                return []CovertLine{
                        cl("[!]", fmt.Sprintf("All %d checks configured — target is hardened", checkCount), p.Locked),
                        cl("[!]", p.Tagline, p.DimLocked),
                }
        }
        if p.Vulnerable == 0 {
                return []CovertLine{
                        cl("[!]", "Infrastructure hardened — but secrets are leaking", p.SRed),
                        cl("[!]", "Rotate exposed credentials immediately.", p.Alt),
                }
        }
        vectors := p.Vulnerable + p.FindingCount
        var lines []CovertLine
        if vectors <= 2 && p.Vulnerable <= 1 {
                lines = append(lines, cl("[!]", fmt.Sprintf("%d attack vector%s available — mostly locked down", vectors, PluralS(vectors)), p.Locked))
                if p.FindingCount > 0 {
                        lines = append(lines, cl("[!]", "Rotate exposed credentials.", p.Alt))
                } else if p.Tagline != "" {
                        lines = append(lines, cl("[!]", p.Tagline, p.DimLocked))
                }
        } else {
                lines = append(lines, cl("[!]", fmt.Sprintf("%d of %d attack vectors available", vectors, checkCount), p.SRed))
                if p.FindingCount > 0 {
                        lines = append(lines, cl("[!]", "Leaked secrets make infrastructure gaps worse.", p.Alt))
                } else if p.Tagline != "" {
                        lines = append(lines, cl("[!]", p.Tagline, p.Alt))
                }
        }
        return lines
}

func RenderCovertLines(svg *strings.Builder, lines []CovertLine, startY int, rc CovertRenderCtx) (lineIdx, y int) {
        y = startY
        for _, line := range lines {
                if line.Text == "" && line.Prefix == "" {
                        y += rc.LineH / 2
                        continue
                }

                delay := rc.ResultStartAt + float64(lineIdx)*0.12

                color := line.Color
                if color == "" {
                        color = rc.Alt
                }

                pfxColor := line.PrefixColor
                if pfxColor == "" && line.Prefix != "" {
                        pfxColor = CovertPrefixColor(line.Prefix, rc.DimLocked, rc.SRed, rc.Alt)
                }

                svg.WriteString(fmt.Sprintf(`<g opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.15s" begin="%.2fs" fill="freeze"/>`, delay))

                if line.Link != "" {
                        svg.WriteString(fmt.Sprintf(`<a href="%s" target="_blank">`, line.Link))
                }

                RenderCovertLineText(svg, line, y, pfxColor, color, rc)

                if line.Link != "" {
                        svg.WriteString(`</a>`)
                }
                svg.WriteString(`</g>`)
                y += rc.LineH
                lineIdx++
        }
        return lineIdx, y
}

func RenderCovertLineText(svg *strings.Builder, line CovertLine, y int, pfxColor, color string, rc CovertRenderCtx) {
        if line.Prefix == "" {
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        rc.XPad, y, color, rc.FontSize, rc.MonoFont, line.Text,
                ))
                return
        }
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                rc.XPad, y, pfxColor, rc.FontSize, rc.MonoFont, line.Prefix,
        ))
        if line.Desc != "" {
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        rc.XPad+28, y, color, rc.FontSize, rc.MonoFont, line.Text,
                ))
                descX := rc.XPad + 28 + len(line.Text)*rc.CharW
                dc := line.DescColor
                if dc == "" {
                        dc = color
                }
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        descX, y, dc, rc.FontSize, rc.MonoFont, line.Desc,
                ))
        } else {
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        rc.XPad+28, y, color, rc.FontSize, rc.MonoFont, line.Text,
                ))
        }
}

func RenderCovertFooter(svg *strings.Builder, lineIdx, y int, rc CovertRenderCtx, domainDisplay, scanTimeStr string) {
        planetText := "#HackThePlanet!   |  #2600"
        owlDelay := rc.ResultStartAt + float64(lineIdx)*0.12
        owlY := y - rc.LineH + 2
        owlX := rc.XPad + 28 + len(planetText)*rc.CharW - 14
        svg.WriteString(fmt.Sprintf(`<g opacity="0" transform="translate(%d,%d) scale(0.8)"><animate attributeName="opacity" from="0" to="0.9" dur="0.3s" begin="%.2fs" fill="freeze"/>`, owlX, owlY-11, owlDelay))
        svg.WriteString(fmt.Sprintf(`<circle cx="4" cy="5" r="3" fill="none" stroke="%s" stroke-width="1"/>`, rc.Alt))
        svg.WriteString(fmt.Sprintf(`<circle cx="12" cy="5" r="3" fill="none" stroke="%s" stroke-width="1"/>`, rc.Alt))
        svg.WriteString(fmt.Sprintf(`<circle cx="4" cy="5" r="1.2" fill="%s"/>`, rc.SRed))
        svg.WriteString(fmt.Sprintf(`<circle cx="12" cy="5" r="1.2" fill="%s"/>`, rc.SRed))
        svg.WriteString(fmt.Sprintf(`<path d="M7,3 L8,0 L9,3" fill="none" stroke="%s" stroke-width="0.8"/>`, rc.Alt))
        svg.WriteString(fmt.Sprintf(`<path d="M3,8 Q8,14 13,8" fill="none" stroke="%s" stroke-width="0.8"/>`, rc.Alt))
        svg.WriteString(`</g>`)

        bottomY1 := y + 6
        bottomDelay := owlDelay + 0.3
        svg.WriteString(fmt.Sprintf(`<g opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.15s" begin="%.2fs" fill="freeze"/>`, bottomDelay))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">┌──(kali㉿kali)-[~/recon/%s]</text>`,
                rc.XPad, bottomY1, rc.Alt, rc.FontSize, rc.MonoFont, domainDisplay,
        ))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" text-anchor="end">%s</text>`,
                rc.Width-rc.XPad, bottomY1, rc.Alt, rc.FontSize, rc.MonoFont, scanTimeStr,
        ))
        bottomY2 := bottomY1 + rc.LineH
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">└─$</text>`,
                rc.XPad, bottomY2, rc.Alt, rc.FontSize, rc.MonoFont,
        ))
        svg.WriteString(fmt.Sprintf(
                `<rect x="%d" y="%d" width="2" height="%d" fill="%s" class="cursor"/>`,
                rc.XPad+4*rc.CharW, bottomY2-10, 12, rc.SRed,
        ))
        svg.WriteString(`</g>`)
}

func BadgeSVGCovert(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, baseURL string) []byte {
        riskLabel, riskColorName := ExtractPostureRisk(results)
        score := ExtractPostureScore(results)
        if IsGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskColorName = "warning"
                score = -1
        }
        nodes := ExtractProtocolIndicators(results)
        vulnerable := CountVulnerable(nodes)
        exposure := ExtractExposure(results)

        covertLabel := CovertRiskLabel(riskColorName, riskLabel)
        tagline := CovertTagline(riskColorName, riskLabel)

        domainDisplay := domain
        if len(domainDisplay) > 35 {
                domainDisplay = domainDisplay[:32] + "..."
        }

        scoreText := "--"
        if score >= 0 {
                scoreText = strconv.Itoa(score)
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        const (
                width    = 460
                lineH    = 15
                fontSize = 11
                xPad     = 14
                charW    = 7
                monoFont = "'Hack','Fira Code','JetBrains Mono','Menlo','Monaco','Source Code Pro','SF Mono','Ubuntu Mono','Courier New',monospace"
        )

        sRed := hexScRed
        alt := "#664d2e"
        locked := hexScGreen
        dimLocked := "#2d7a47"

        cl := func(pfx, txt, c string) CovertLine {
                return CovertLine{Prefix: pfx, Text: txt, Color: c}
        }

        var lines []CovertLine

        lines = append(lines, cl("", "", ""))

        lines = append(lines, cl("[*]", fmt.Sprintf("Target: %s", domainDisplay), alt))
        lines = append(lines, cl("[*]", fmt.Sprintf("Score: %s/100 — %s", scoreText, covertLabel), ScotopicRiskColor(riskColorName)))
        lines = append(lines, cl("", "", ""))

        protocols := []string{"SPF", "DKIM", protoDMARC, protoDNSSEC, "DANE", protoMTASTS, protoTLSRPT, "BIMI", "CAA"}
        for i, p := range protocols {
                if i < len(nodes) {
                        lines = append(lines, CovertProtocolLine(p, nodes[i].Status))
                }
        }

        web3Status := ExtractWeb3Status(results)
        if web3Status != "" {
                lines = append(lines, CovertProtocolLine("Web3", web3Status))
        }

        lines = append(lines, CovertExposureLines(exposure, sRed, alt, baseURL, scanID)...)

        lines = append(lines, cl("", "", ""))

        lines = append(lines, CovertSummaryLines(CovertSummaryParams{
                Vulnerable: vulnerable, FindingCount: exposure.FindingCount,
                Tagline: tagline, Locked: locked, DimLocked: dimLocked,
                SRed: sRed, Alt: alt,
        })...)

        lines = append(lines, cl("", "", ""))
        hashDisplay := postureHash
        if len(hashDisplay) > 8 {
                hashDisplay = hashDisplay[:8]
        }
        if hashDisplay == "" {
                hashDisplay = "--------"
        }
        reportURL := fmt.Sprintf("%s/analyze?domain=%s", baseURL, domain)
        hashURL := fmt.Sprintf("%s/analysis/%d/view/C#intelligence-metadata", baseURL, scanID)
        scanLine := cl("", fmt.Sprintf("[*] %s sha3:%s | scan #%d", scanDate, hashDisplay, scanID), alt)
        scanLine.Link = reportURL
        lines = append(lines, scanLine)
        shaLine := cl("", "[*] SHA-3 (Keccak-512) NIST FIPS 202", sRed)
        shaLine.Link = hashURL
        lines = append(lines, shaLine)
        planetLine := cl("&amp;&amp;", "#HackThePlanet!   |  #2600", sRed)
        planetLine.PrefixColor = sRed
        planetLine.Link = baseURL
        lines = append(lines, planetLine)

        height := len(lines)*lineH + 24 + 2*lineH + 4 + 2*lineH + 10

        var svg strings.Builder

        cmdText := fmt.Sprintf("dnstool -R -BC %s", domainDisplay)
        cmdLen := len(cmdText)
        typeTime := float64(cmdLen) * 0.06
        cmdDoneAt := 0.8 + typeTime
        resultStartAt := cmdDoneAt + 0.4

        svg.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Recon: %s — %s">
  <title>DNS Recon: %s — %s</title>
  <defs>
    <linearGradient id="tbg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1a0505"/>
      <stop offset="1" stop-color="#0a0000"/>
    </linearGradient>
  </defs>
  <style>
    @keyframes blink { 0%%,49%% {opacity:1} 50%%,100%% {opacity:0} }
    @keyframes typeIn { from {opacity:0} to {opacity:1} }
    @keyframes fadeIn { from {opacity:0} to {opacity:1} }
    .cursor { animation: blink 0.8s step-end infinite; animation-delay: 0s; }
    .cursor-hide { animation: blink 0.8s step-end infinite; }
  </style>
  <rect width="%d" height="%d" rx="6" fill="url(#tbg)"/>
  <rect x=".5" y=".5" width="%d" height="%d" rx="6" fill="none" stroke="#3a1515"/>`,
                width, height, width, height,
                domain, covertLabel,
                domain, covertLabel,
                width, height,
                width-1, height-1,
        ))

        svg.WriteString(fmt.Sprintf(`
  <circle cx="16" cy="10" r="4" fill="#ff5f57"/>
  <circle cx="28" cy="10" r="4" fill="#febc2e"/>
  <circle cx="40" cy="10" r="4" fill="#28c840"/>
  <text x="60" y="13" fill="%s" font-size="9" font-family="%s">kali@kali: ~/recon/%s</text>`,
                alt, monoFont, domainDisplay,
        ))

        scanTimeStr := scanTime.UTC().Format("15:04") + "Z"

        promptY := 28
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">┌──(kali㉿kali)-[~/recon/%s]</text>`,
                xPad, promptY, alt, fontSize, monoFont, domainDisplay,
        ))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" text-anchor="end">%s</text>`,
                width-xPad, promptY, alt, fontSize, monoFont, scanTimeStr,
        ))
        promptY2 := promptY + lineH
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">└─$</text>`,
                xPad, promptY2, alt, fontSize, monoFont,
        ))

        cmdX := xPad + 4*charW
        for i, ch := range cmdText {
                delay := 0.8 + float64(i)*0.06
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.01s" begin="%.2fs" fill="freeze"/>%c</text>`,
                        cmdX+i*charW, promptY2, sRed, fontSize, monoFont, delay, ch,
                ))
        }

        rc := CovertRenderCtx{
                XPad: xPad, LineH: lineH, FontSize: fontSize, CharW: charW,
                Width: width, MonoFont: monoFont, DimLocked: dimLocked,
                SRed: sRed, Alt: alt, ResultStartAt: resultStartAt,
        }

        lineIdx, y := RenderCovertLines(&svg, lines, promptY2+lineH+4, rc)

        RenderCovertFooter(&svg, lineIdx, y, rc, domainDisplay, scanTimeStr)

        svg.WriteString(`</svg>`)

        return []byte(svg.String())
}

