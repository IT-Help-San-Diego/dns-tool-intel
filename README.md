# DNS Tool — Intelligence Engine

> **Private intelligence modules for DNS Tool.**

This repository contains proprietary analysis modules for [DNS Tool](https://github.com/careyjames/DnsToolWeb):

- Edge CDN detection
- SaaS TXT record classification
- Infrastructure provider identification
- IP investigation modules
- AI surface analysis (HTTP, robots.txt, llms.txt, poisoning, scanner)
- Posture diff engine
- Provider enrichment

## Build

These modules compile with the `intel` build tag:

```bash
go build -tags intel ./go-server/...
```

## Mirrors

This repository is the canonical source. A read-only mirror is maintained at [codeberg.org/careybalboa/dns-tool-intel](https://codeberg.org/careybalboa/dns-tool-intel) (private).

## License

[Business Source License 1.1](LICENSE) — IT Help San Diego Inc.
