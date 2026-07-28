        let SOURCES = [
            { id: 'root',  label: 'Root / TLD',      sub: 'IANA Root Zone\nTLD Registries',       color: COLORS.source, zone: 'source' },
            { id: 'rdap',  label: 'RDAP / WHOIS',    sub: 'Registration Data\nAccess Protocol',   color: COLORS.intel,  zone: 'source' },
            { id: 'ct',    label: 'CT / Subdomains',  sub: 'crt.sh \u00b7 Certspotter\nTransparency Logs', color: COLORS.intel,  zone: 'source' },
            { id: 'cisa',  label: 'CISA / Threat',    sub: 'BOD 19-02\nIP Scanner Detection',     color: COLORS.intel,  zone: 'source' },
            { id: 'probes', label: 'Probe Fleet',     sub: 'SMTP \u00b7 DANE \u00b7 TLS\nNmap \u00b7 testssl.sh', color: COLORS.source, zone: 'source' }
        ];

        let HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', color: COLORS.source, zone: 'hub', x: 0, y: 0, targetX: 0, targetY: 0, radius: 44, _initialized: false, shape: 'hub' };

        let ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', color: COLORS.engine, zone: 'engine', x: 0, y: 0, targetX: 0, targetY: 0, radius: 54, _initialized: false };

        let CONFIDENCE = [
            { id: 'ietf',  label: 'IETF Metadata',   sub: 'RFC Status \u00b7 Errata\nDraft Tracker',  color: COLORS.intel,  zone: 'confidence' },
            { id: 'icae',  label: 'ICAE',  sub: 'Accuracy Audit',   color: '#ef9a9a', zone: 'confidence' },
            { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit',   color: '#a5d6a7', zone: 'confidence' },
            { id: 'ede',   label: 'EDE',   sub: 'Epistemic\nDisclosure', color: '#ffab91', zone: 'confidence' }
        ];

        let STORAGE = [
            { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results \u00b7 History\nDrift \u00b7 Analytics', color: COLORS.storage, zone: 'storage' },
            { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', color: '#ffcc80', zone: 'storage' },
            { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', color: '#81c784', zone: 'storage' }
        ];

        let PROTOCOLS = [
            { id: 'spf',    label: 'SPF',     rfc: '7208',  cat: 'email' },
            { id: 'dkim',   label: 'DKIM',    rfc: '6376',  cat: 'email' },
            { id: 'dmarc',  label: 'DMARC',   rfc: '7489',  cat: 'email' },
            { id: 'dnssec', label: 'DNSSEC',  rfc: '4035',  cat: 'policy' },
            { id: 'dane',   label: 'DANE',    rfc: '6698',  cat: 'transport' },
            { id: 'mtasts', label: 'MTA-STS', rfc: '8461',  cat: 'transport' },
            { id: 'tlsrpt', label: 'TLS-RPT', rfc: '8460',  cat: 'transport' },
            { id: 'bimi',   label: 'BIMI',    rfc: 'draft', cat: 'brand' },
            { id: 'caa',    label: 'CAA',     rfc: '8659',  cat: 'policy' }
        ];

        let OUTPUTS = [
            { id: 'reports', label: 'Reports',    sub: 'Engineer \u00b7 Executive\nRecon \u00b7 Comparison', color: COLORS.output, zone: 'output' },
            { id: 'jsonapi', label: 'JSON API',   sub: 'Analysis \u00b7 Checksums\nSubdomains \u00b7 Health', color: COLORS.output, zone: 'output' },
            { id: 'seo',    label: 'Schema.org',  sub: 'JSON-LD Structured Data\nGoogle \u00b7 Rich Results', color: COLORS.output, zone: 'output' },
            { id: 'badges', label: 'SVG Badges',  sub: 'Posture Indicators\nEmbeddable', color: COLORS.output, zone: 'output' }
        ];

        let PROTO_EDGES = [
            { from: 'dmarc', to: 'spf',    type: 'hard',  label: 'alignment',     labelT: 0.45 },
            { from: 'dmarc', to: 'dkim',   type: 'hard',  label: 'alignment',     labelT: 0.45 },
            { from: 'dane',  to: 'dnssec', type: 'hard',  label: 'requires',      labelT: 0.35 },
            { from: 'bimi',  to: 'dmarc',  type: 'hard',  label: 'p=quarantine+', labelT: 0.5 },
            { from: 'tlsrpt', to: 'mtasts', type: 'soft', label: 'reports',       labelT: 0.5 },
            { from: 'tlsrpt', to: 'dane',  type: 'soft',  label: 'reports',       labelT: 0.4 },
            { from: 'caa',   to: 'dnssec', type: 'soft',  label: 'strengthens',   labelT: 0.5 }
        ];

        let allNodes = {};

        SOURCES.forEach(function(s) {
            s.x = 0; s.y = 0; s.targetX = 0; s.targetY = 0;
            s.radius = 30; s._initialized = false; s.shape = 'rect';
            allNodes[s.id] = s;
        });
        allNodes[HUB.id] = HUB;
        allNodes[ENGINE.id] = ENGINE;

        CONFIDENCE.forEach(function(c) {
            c.x = 0; c.y = 0; c.targetX = 0; c.targetY = 0;
            c.radius = (c.id === 'ede') ? 48 : (c.id === 'ietf') ? 36 : 42;
            c._initialized = false; c.shape = (c.id === 'ietf') ? 'rect' : 'diamond';
            allNodes[c.id] = c;
        });

        STORAGE.forEach(function(s) {
            s.x = 0; s.y = 0; s.targetX = 0; s.targetY = 0;
            s.radius = (s.id === 'postgres') ? 36 : (s.id === 'wayback') ? 32 : 34;
            s._initialized = false; s.shape = 'cylinder';
            allNodes[s.id] = s;
        });

        PROTOCOLS.forEach(function(p) {
            p.x = 0; p.y = 0; p.targetX = 0; p.targetY = 0;
            p.radius = 36; p.color = COLORS[p.cat]; p.shape = 'circle';
            p._initialized = false; p.zone = 'protocol';
            allNodes[p.id] = p;
        });

        OUTPUTS.forEach(function(o) {
            o.x = 0; o.y = 0; o.targetX = 0; o.targetY = 0;
            o.radius = 36; o._initialized = false; o.shape = 'hexagon';
            allNodes[o.id] = o;
        });

        let FLOW_EDGES = [];
        FLOW_EDGES.push({ from: 'hub', to: 'engine', type: 'flow', label: '' });
        SOURCES.forEach(function(s) {
            FLOW_EDGES.push({ from: s.id, to: 'hub', type: 'flow', label: '' });
        });
        FLOW_EDGES.push({ from: 'ietf', to: 'engine', type: 'flow', label: 'informs' });
        FLOW_EDGES.push({ from: 'ietf', to: 'icae', type: 'flow', label: 'informs' });
        FLOW_EDGES.push({ from: 'ietf', to: 'icuae', type: 'flow', label: 'informs' });
        FLOW_EDGES.push({ from: 'engine', to: 'icae', type: 'flow', label: '' });
        FLOW_EDGES.push({ from: 'engine', to: 'icuae', type: 'flow', label: '' });
        FLOW_EDGES.push({ from: 'icae', to: 'ede', type: 'flow', label: 'discloses' });
        FLOW_EDGES.push({ from: 'icuae', to: 'ede', type: 'flow', label: 'discloses' });
        FLOW_EDGES.push({ from: 'engine', to: 'postgres', type: 'flow', label: 'persist' });
        FLOW_EDGES.push({ from: 'postgres', to: 'fixtures', type: 'flow', label: 'seeds' });
        FLOW_EDGES.push({ from: 'postgres', to: 'wayback', type: 'flow', label: 'archives' });
        PROTOCOLS.forEach(function(p) {
            FLOW_EDGES.push({ from: 'engine', to: p.id, type: 'flow', label: '' });
        });
        OUTPUTS.forEach(function(o) {
            FLOW_EDGES.push({ from: 'engine', to: o.id, type: 'flow', label: '' });
        });
        FLOW_EDGES.push({ from: 'postgres', to: 'reports', type: 'flow', label: 'history' });
