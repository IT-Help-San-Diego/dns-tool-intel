#!/usr/bin/env python3
"""Generate OG social card images for DNS Tool.

Layout: 1200x630, centered composition.
- Owl emblem (~180px) centered horizontally, positioned in upper region
- Title large and centered
- Subtitle centered below
- Protocol tags in accent green, centered
- Highlight in accent purple, centered
- Detail line centered
- Company + URL at bottom with gold accent line
"""

import os
from PIL import Image, ImageDraw, ImageFont

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "images")
OWL_PATH = os.path.join(STATIC_DIR, "owl-signature.png")

W, H = 1200, 630
BG_COLOR = (13, 17, 23)
TEXT_PRIMARY = (230, 237, 243)
TEXT_SECONDARY = (139, 148, 158)
TEXT_MUTED = (110, 118, 129)
TEXT_DIM = (72, 79, 88)
ACCENT_GREEN = (126, 231, 135)
ACCENT_PURPLE = (201, 160, 255)
ACCENT_GOLD = (200, 168, 120)

FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def load_font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except (OSError, IOError):
        return ImageFont.load_default()


def text_center_x(draw, text, font):
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    return (W - tw) // 2


def generate(filename, title, subtitle, tags, highlight, detail):
    img = Image.new("RGBA", (W, H), BG_COLOR)
    draw = ImageDraw.Draw(img)

    owl = Image.open(OWL_PATH).convert("RGBA")
    owl_size = 180
    owl = owl.resize((owl_size, owl_size), Image.LANCZOS)
    owl_x = (W - owl_size) // 2
    owl_y = 36
    img.paste(owl, (owl_x, owl_y), owl)

    content_top = owl_y + owl_size + 24

    font_title = load_font(FONT_BOLD, 48)
    font_subtitle = load_font(FONT_REGULAR, 21)
    font_tags = load_font(FONT_REGULAR, 15)
    font_highlight = load_font(FONT_BOLD, 17)
    font_detail = load_font(FONT_REGULAR, 14)
    font_footer = load_font(FONT_REGULAR, 12)

    y = content_top
    x = text_center_x(draw, title, font_title)
    draw.text((x, y), title, fill=TEXT_PRIMARY, font=font_title)
    y += 58

    x = text_center_x(draw, subtitle, font_subtitle)
    draw.text((x, y), subtitle, fill=TEXT_SECONDARY, font=font_subtitle)
    y += 38

    x = text_center_x(draw, tags, font_tags)
    draw.text((x, y), tags, fill=ACCENT_GREEN, font=font_tags)
    y += 30

    x = text_center_x(draw, highlight, font_highlight)
    draw.text((x, y), highlight, fill=ACCENT_PURPLE, font=font_highlight)
    y += 30

    x = text_center_x(draw, detail, font_detail)
    draw.text((x, y), detail, fill=TEXT_MUTED, font=font_detail)

    line_w = 160
    line_y = H - 78
    line_x1 = (W - line_w) // 2
    line_x2 = line_x1 + line_w
    draw.line([(line_x1, line_y), (line_x2, line_y)], fill=ACCENT_GOLD + (120,), width=2)

    company = "IT Help San Diego Inc."
    url = "dnstool.it-help.tech"
    x = text_center_x(draw, company, font_footer)
    draw.text((x, H - 66), company, fill=TEXT_DIM, font=font_footer)
    x = text_center_x(draw, url, font_footer)
    draw.text((x, H - 46), url, fill=TEXT_DIM, font=font_footer)

    out_path = os.path.join(STATIC_DIR, filename)
    img_rgb = Image.new("RGB", (W, H), BG_COLOR)
    img_rgb.paste(img, mask=img.split()[3] if img.mode == "RGBA" else None)
    img_rgb.save(out_path, "PNG", optimize=True)
    size_kb = os.path.getsize(out_path) // 1024
    print(f"Generated {filename} ({size_kb} KB)")


cards = [
    ("og-image.png",
     "DNS Tool",
     "Domain Security Intelligence",
     "SPF \u00b7 DKIM \u00b7 DMARC \u00b7 DANE \u00b7 DNSSEC \u00b7 BIMI \u00b7 MTA-STS \u00b7 TLS-RPT \u00b7 CAA",
     "9 Protocols Evaluated \u00b7 RFC-Verified",
     "Intelligence Confidence Audit Engine (ICAE)"),
    ("og-toolkit.png",
     "Field Tech Toolkit",
     "Guided Network Troubleshooting for Everyone",
     "What's My IP \u00b7 Port Check \u00b7 DNS Test \u00b7 Traceroute \u00b7 Network Chain",
     "Step-by-Step Diagnostics \u00b7 Educational",
     "Wizard-Style Flow with RFC Citations"),
    ("og-investigate.png",
     "IP Intelligence",
     "Investigate IP-to-Domain Relationships",
     "ASN \u00b7 Geolocation \u00b7 Reverse DNS \u00b7 RDAP \u00b7 SPF Authorization",
     "Evidence-Based Attribution \u00b7 Multi-Source",
     "Certificate Transparency \u00b7 Subdomain Discovery"),
    ("og-email-header.png",
     "Email Intelligence",
     "Email Header Analyzer \u00b7 Spoofing Detection",
     "SPF \u00b7 DKIM \u00b7 DMARC \u00b7 Delivery Routing \u00b7 Spam Vendor Detection",
     "Authentication Verification \u00b7 RFC-Compliant",
     "OpenPhish Integration \u00b7 Brand Mismatch Detection"),
    ("og-ttl-tuner.png",
     "TTL Tuner",
     "Tune Your DNS for Speed, Reliability, and Control",
     "A \u00b7 AAAA \u00b7 MX \u00b7 NS \u00b7 SOA \u00b7 TXT \u00b7 CNAME \u00b7 SRV \u00b7 CAA",
     "Provider-Aware \u00b7 RFC-Cited \u00b7 Copy-Paste Instructions",
     "Cloudflare \u00b7 Route 53 \u00b7 BIND \u00b7 GoDaddy \u00b7 All Providers"),
    ("og-forgotten-domain.png",
     "Forgotten Domain",
     "Silence Is Not Protection",
     "SPF: v=spf1 -all    DMARC: p=reject    MX: 0 .",
     "Three Records Separate Protection from Impersonation",
     "If a domain sends no mail, publish the policy."),
]

if __name__ == "__main__":
    for args in cards:
        generate(*args)
