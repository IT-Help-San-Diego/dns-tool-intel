#!/usr/bin/env bash
set -euo pipefail

STATIC_DIR="$(cd "$(dirname "$0")/.." && pwd)/static/images"
OWL="$STATIC_DIR/owl-of-athena.png"
BG_COLOR="#0d1117"
W=1200
H=630

generate() {
  local file="$1" title="$2" subtitle="$3" tags="$4" highlight="$5" detail="$6"
  local out="$STATIC_DIR/$file"

  convert -size ${W}x${H} "xc:${BG_COLOR}" \
    \( "$OWL" -resize 88x88 -background none \
       \( +clone -alpha extract -morphology Dilate Disk:1 \
          -background "#1a2332" -alpha shape \) \
       +swap -compose Over -composite \
    \) -gravity North -geometry +0+40 -compose Over -composite \
    \( -size ${W}x1 "xc:${BG_COLOR}" \) \
    -gravity North -geometry +0+138 -compose Over -composite \
    -font DejaVu-Sans-Bold -pointsize 46 -fill "#e6edf3" \
    -gravity North -annotate +0+150 "$title" \
    -font DejaVu-Sans -pointsize 19 -fill "#8b949e" \
    -gravity North -annotate +0+210 "$subtitle" \
    -font DejaVu-Sans -pointsize 14 -fill "#7ee787" \
    -gravity North -annotate +0+252 "$tags" \
    -font DejaVu-Sans-Bold -pointsize 16 -fill "#c9a0ff" \
    -gravity North -annotate +0+286 "$highlight" \
    -font DejaVu-Sans -pointsize 13 -fill "#6e7681" \
    -gravity North -annotate +0+316 "$detail" \
    -font DejaVu-Sans -pointsize 12 -fill "#484f58" \
    -gravity South -annotate +0+62 "IT Help San Diego Inc." \
    -font DejaVu-Sans -pointsize 12 -fill "#484f58" \
    -gravity South -annotate +0+44 "dnstool.it-help.tech" \
    \( -size 200x2 "xc:none" \
       -draw "stroke #388bfd stroke-opacity 0.6 stroke-width 2 line 0,1 200,1" \
    \) -gravity South -geometry +0+30 -compose Over -composite \
    -quality 95 "$out"

  echo "Generated $file ($(du -k "$out" | cut -f1) KB)"
}

generate "og-image.png" \
  "DNS Tool" \
  "Domain Security Intelligence" \
  "SPF · DKIM · DMARC · DANE · DNSSEC · BIMI · MTA-STS · TLS-RPT · CAA" \
  "9 Protocols Evaluated · RFC-Verified" \
  "Intelligence Confidence Audit Engine (ICAE)"

generate "og-toolkit.png" \
  "Field Tech Toolkit" \
  "Guided Network Troubleshooting for Everyone" \
  "What's My IP · Port Check · DNS Test · Traceroute · Network Chain" \
  "Step-by-Step Diagnostics · Educational" \
  "Wizard-Style Flow with RFC Citations"

generate "og-investigate.png" \
  "IP Intelligence" \
  "Investigate IP-to-Domain Relationships" \
  "ASN · Geolocation · Reverse DNS · RDAP · SPF Authorization" \
  "Evidence-Based Attribution · Multi-Source" \
  "Certificate Transparency · Subdomain Discovery"

generate "og-email-header.png" \
  "Email Intelligence" \
  "Email Header Analyzer · Spoofing Detection" \
  "SPF · DKIM · DMARC · Delivery Routing · Spam Vendor Detection" \
  "Authentication Verification · RFC-Compliant" \
  "OpenPhish Integration · Brand Mismatch Detection"

generate "og-ttl-tuner.png" \
  "TTL Tuner" \
  "Tune Your DNS for Speed, Reliability, and Control" \
  "A · AAAA · MX · NS · SOA · TXT · CNAME · SRV · CAA" \
  "Provider-Aware · RFC-Cited · Copy-Paste Instructions" \
  "Cloudflare · Route 53 · BIND · GoDaddy · All Providers"

generate "og-forgotten-domain.png" \
  "Forgotten Domain" \
  "Silence Is Not Protection" \
  "SPF: v=spf1 -all    DMARC: p=reject    MX: 0 ." \
  "Three Records Separate Protection from Impersonation" \
  "If a domain sends no mail, publish the policy."

echo "All OG images generated."
