import './_group.css';
import { Search, ChevronDown, ShieldAlert } from 'lucide-react';

function HackerSkull({ size = 20, color = '#c43c3c' }: { size?: number; color?: string }) {
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
      <svg width={size * 0.7} height={size * 0.7} viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style={{ display: 'block' }}>
        {/* Crossbones — behind skull, two thick bones in an X */}
        <g>
          {/* Bone 1: top-left to bottom-right */}
          <rect x="2" y="36" width="60" height="5" rx="2.5" fill={color} transform="rotate(-25 32 38.5)" />
          <circle cx="7" cy="32.5" r="4" fill={color} />
          <circle cx="3" cy="37.5" r="4" fill={color} />
          <circle cx="57" cy="39.5" r="4" fill={color} />
          <circle cx="61" cy="44.5" r="4" fill={color} />
          {/* Bone 2: top-right to bottom-left */}
          <rect x="2" y="36" width="60" height="5" rx="2.5" fill={color} transform="rotate(25 32 38.5)" />
          <circle cx="57" cy="32.5" r="4" fill={color} />
          <circle cx="61" cy="37.5" r="4" fill={color} />
          <circle cx="7" cy="44.5" r="4" fill={color} />
          <circle cx="3" cy="39.5" r="4" fill={color} />
        </g>
        {/* Skull — sits on top of bones */}
        <g>
          {/* Cranium */}
          <path d="M32 4 C18 4 10 14 10 24 C10 30 13 34 16 37 L16 42 C16 44 18 46 21 46 L26 46 L26 42 L28 46 L36 46 L38 42 L38 46 L43 46 C46 46 48 44 48 42 L48 37 C51 34 54 30 54 24 C54 14 46 4 32 4 Z" fill={color} />
          {/* Eye sockets */}
          <ellipse cx="24" cy="22" rx="5.5" ry="6" fill="#0d1117" />
          <ellipse cx="40" cy="22" rx="5.5" ry="6" fill="#0d1117" />
          {/* Nose cavity */}
          <path d="M30 32 L32 28 L34 32 Z" fill="#0d1117" />
          {/* Teeth gaps */}
          <rect x="25.5" y="38" width="1.2" height="8" fill="#0d1117" />
          <rect x="31.4" y="38" width="1.2" height="8" fill="#0d1117" />
          <rect x="37.3" y="38" width="1.2" height="8" fill="#0d1117" />
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
