import './_group.css';
import { Search, ChevronDown, ShieldAlert } from 'lucide-react';

function HackerSkull({ size = 20, color = '#c43c3c' }: { size?: number; color?: string }) {
  const bg = '#0d1117';
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: size,
      height: size,
      borderRadius: '50%',
      background: 'rgba(196,60,60,0.08)',
      border: '1px solid rgba(196,60,60,0.2)',
      boxShadow: '0 0 6px rgba(196,60,60,0.1), inset 0 1px 1px rgba(255,255,255,0.04)',
      flexShrink: 0,
    }}>
      <svg
        width={Math.round(size * 0.72)}
        height={Math.round(size * 0.72)}
        viewBox="0 0 100 100"
        xmlns="http://www.w3.org/2000/svg"
        style={{ display: 'block' }}
      >
        {/*
         * CLASSIC JOLLY ROGER LAYOUT — skull dominant, bones behind.
         *
         * Bbox: (5,10) → (95,90), center = (50,50) ✓
         * Skull: y=10→65 = 55 units (69% of composition) — DOMINANT
         * Bones: cross at (50,50) behind skull; tips peek from sides
         * Upper bone tips at y=15/23 — visible flanking the narrow cranium
         * Lower bone tips at y=77/85 — visible below the jaw
         */}

        {/* === CROSSBONES (behind skull — rendered first) === */}
        <g>
          <line x1="14" y1="19" x2="86" y2="81" stroke={color} strokeWidth="7" strokeLinecap="round" />
          <circle cx="10" cy="15" r="5" fill={color} />
          <circle cx="10" cy="23" r="5" fill={color} />
          <circle cx="90" cy="77" r="5" fill={color} />
          <circle cx="90" cy="85" r="5" fill={color} />

          <line x1="86" y1="19" x2="14" y2="81" stroke={color} strokeWidth="7" strokeLinecap="round" />
          <circle cx="90" cy="15" r="5" fill={color} />
          <circle cx="90" cy="23" r="5" fill={color} />
          <circle cx="10" cy="77" r="5" fill={color} />
          <circle cx="10" cy="85" r="5" fill={color} />
        </g>

        {/* === SKULL (on top — rendered second, covers bone crossing) === */}
        <g>
          <path d={`
            M50 10
            C30 10  18 24  18 38
            C18 48  23 53  28 57
            L28 60 C28 62 30 65 34 65
            L41 65 L41 61 L44 65
            L56 65 L59 61 L59 65
            L66 65 C70 65 72 62 72 60
            L72 57 C77 53 82 48 82 38
            C82 24  70 10  50 10 Z
          `} fill={color} />
          <ellipse cx="38" cy="35" rx="8" ry="8" fill={bg} />
          <ellipse cx="62" cy="35" rx="8" ry="8" fill={bg} />
          <path d="M46 49 L50 43 L54 49 Z" fill={bg} />
          <rect x="42" y="55" width="2" height="10" fill={bg} rx="0.5" />
          <rect x="49" y="55" width="2" height="10" fill={bg} rx="0.5" />
          <rect x="56" y="55" width="2" height="10" fill={bg} rx="0.5" />
        </g>
      </svg>
    </span>
  );
}

export function Refined() {
  return (
    <div style={{ background: '#0d1117', minHeight: '100vh', padding: 0 }}>
      {/* Nav bar */}
      <nav style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0.5rem 1.5rem',
        borderBottom: '1px solid #21262d',
        background: '#0d1117',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <img
            src="https://dnstool.it-help.tech/static/images/owl-of-athena-160.png"
            alt="DNS Tool"
            width={32}
            height={32}
            style={{ borderRadius: '50%' }}
          />
          <span style={{ color: '#fff', fontWeight: 600, fontSize: '1.1rem' }}>DNS Tool</span>
          <span style={{ color: '#8b949e', fontSize: '0.75rem' }}>v26.38.05</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <span style={{
            background: 'rgba(232,181,74,0.15)',
            color: '#e8b54a',
            padding: '0.2rem 0.6rem',
            borderRadius: '4px',
            fontSize: '0.7rem',
            fontWeight: 600,
          }}>Developing!</span>
        </div>
      </nav>

      {/* Hero Section */}
      <div style={{ padding: '3rem 0 2rem', textAlign: 'center' }}>
        <div style={{ maxWidth: '900px', margin: '0 auto', padding: '0 1rem' }}>
          {/* Badge with custom hacker icon */}
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.45rem 1rem',
            borderRadius: '2rem',
            background: 'rgba(200,149,106,0.12)',
            color: '#c8956a',
            fontSize: '0.8rem',
            fontWeight: 600,
            letterSpacing: '0.04em',
            marginBottom: '1rem',
          }}>
            <HackerSkull size={24} color="#c43c3c" />
            <span>DNS SECURITY INTELLIGENCE</span>
          </div>

          {/* H1 */}
          <h1 style={{
            fontSize: '2.5rem',
            fontWeight: 700,
            color: '#e6edf3',
            marginBottom: '0.75rem',
            lineHeight: 1.2,
          }}>
            Domain Security Audit
          </h1>

          {/* Tagline */}
          <p style={{
            fontSize: '1.5rem',
            color: '#8b949e',
            marginBottom: '0.5rem',
          }}>
            We answer the <span style={{ color: '#d4a853' }}>BIG</span> questions.
          </p>

          {/* Subtitle */}
          <p style={{
            fontSize: '1.05rem',
            color: '#8b949e',
            marginBottom: '2rem',
            maxWidth: '600px',
            marginLeft: 'auto',
            marginRight: 'auto',
            lineHeight: 1.6,
          }}>
            Producing <span style={{ color: '#d4a853' }}>Engineer's DNS Intelligence Reports</span> and{' '}
            <span style={{ color: '#d4a853' }}>Executive's DNS Intelligence Briefs</span> with{' '}
            <span style={{ color: '#d4a853' }}>posture&nbsp;scoring</span>
          </p>

          {/* Search Card — tightened */}
          <div style={{
            background: 'linear-gradient(145deg, #161b22 0%, #1a2028 100%)',
            border: '1px solid rgba(48,54,61,0.6)',
            borderRadius: '12px',
            padding: '1.5rem 1.75rem',
            maxWidth: '540px',
            margin: '0 auto',
            boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginBottom: '0.75rem',
              justifyContent: 'center',
            }}>
              <Search size={16} style={{ color: '#8b949e' }} />
              <span style={{ fontSize: '1rem', fontWeight: 500, color: '#e6edf3' }}>Domain Name</span>
            </div>

            {/* Input + Button row */}
            <div style={{ display: 'flex', gap: '0' }}>
              <input
                type="text"
                placeholder="example.com or com"
                readOnly
                style={{
                  flex: 1,
                  padding: '0.7rem 0.85rem',
                  background: '#2b3035',
                  border: '1px solid #495057',
                  borderRight: 'none',
                  borderRadius: '0.5rem 0 0 0.5rem',
                  color: '#8b949e',
                  fontSize: '1rem',
                  outline: 'none',
                  minWidth: 0,
                }}
              />
              <button style={{
                padding: '0.7rem 1.25rem',
                background: '#238636',
                border: '1px solid #2ea043',
                borderRadius: '0 0.5rem 0.5rem 0',
                color: '#fff',
                fontSize: '1rem',
                fontWeight: 500,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                whiteSpace: 'nowrap',
                flexShrink: 0,
              }}>
                <Search size={16} />
                Analyze
              </button>
            </div>

            {/* Hint text — tightened */}
            <p style={{
              fontSize: '0.78rem',
              color: '#6e7681',
              marginTop: '0.75rem',
              lineHeight: 1.55,
              textAlign: 'center',
            }}>
              Enter a domain (e.g., <strong style={{ color: '#c8956a' }}>example.com</strong>) or a top-level zone (e.g., <strong style={{ color: '#c8956a' }}>tech</strong>, <strong style={{ color: '#c8956a' }}>co.uk</strong>) — no https://. TLDs produce a <strong style={{ color: '#8b949e' }}>Registry Zone Health Report</strong>.
            </p>

            {/* Privacy notice — redesigned with hacker skull */}
            <div style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.45rem',
              marginTop: '0.6rem',
              padding: '0.5rem 0.65rem',
              background: 'rgba(196,60,60,0.04)',
              border: '1px solid rgba(196,60,60,0.1)',
              borderRadius: '8px',
            }}>
              <HackerSkull size={18} color="rgba(196,60,60,0.5)" />
              <span style={{
                fontSize: '0.72rem',
                color: '#6e7681',
                lineHeight: 1.5,
              }}>
                DNS lookups may be logged by upstream resolvers and authoritative nameservers.
              </span>
            </div>

            {/* Shopping for a domain — separate clean link */}
            <div style={{
              marginTop: '0.5rem',
              textAlign: 'center',
            }}>
              <button style={{
                background: 'none',
                border: 'none',
                color: '#3fb950',
                fontSize: '0.75rem',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem',
                padding: 0,
              }}>
                <ChevronDown size={12} />
                Shopping for a domain?
              </button>
            </div>

            {/* Advanced Options */}
            <div style={{
              marginTop: '0.6rem',
              textAlign: 'center',
            }}>
              <button style={{
                background: 'none',
                border: 'none',
                color: '#8b949e',
                fontSize: '0.75rem',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem',
                padding: 0,
              }}>
                <span style={{ color: '#58a6ff' }}>⚙</span>
                Advanced Options <span style={{ color: '#6e7681' }}>(optional)</span>
                <ChevronDown size={12} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
