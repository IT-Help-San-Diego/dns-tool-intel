import './_group.css';
import { Search, ChevronDown, ShieldAlert } from 'lucide-react';

function HackerSkull({ size = 14, color = '#c43c3c' }: { size?: number; color?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style={{ verticalAlign: '-2px' }}>
      <path fill={color} d="M15.8,18.5L21.8,20.1L21.4,22L12,19.5L2.6,22L2.1,20.1L8.1,18.5L2,16.9L2.5,15L11.9,17.5L21.3,15L21.8,16.9L15.8,18.5M18,8C18,9.8 17.2,11.3 16,12.4V15H14V13.7L14,13H13V15H11V13H10V13.7L10,15H8V12.4C6.8,11.3 6,9.8 6,8A6,6 0 0,1 12,2A6,6 0 0,1 18,8M11,7.5C11,6.7 10.3,6 9.5,6C8.7,6 8,6.7 8,7.5C8,8.3 8.7,9 9.5,9C10.3,9 11,8.3 11,7.5M13,11L12,9L11,11H13M16,7.5C16,6.7 15.3,6 14.5,6C13.7,6 13,6.7 13,7.5C13,8.3 13.7,9 14.5,9C15.3,9 16,8.3 16,7.5Z" />
    </svg>
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
            <HackerSkull size={20} color="#c43c3c" />
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
              <HackerSkull size={16} color="rgba(196,60,60,0.5)" />
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
