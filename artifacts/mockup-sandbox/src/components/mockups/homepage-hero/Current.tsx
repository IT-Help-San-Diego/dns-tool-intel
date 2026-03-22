import './_group.css';
import { Shield, Search } from 'lucide-react';

export function Current() {
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
          {/* Badge */}
          <div style={{
            display: 'inline-block',
            padding: '0.5rem 1rem',
            borderRadius: '2rem',
            background: 'rgba(200,149,106,0.15)',
            color: '#c8956a',
            fontSize: '0.85rem',
            fontWeight: 600,
            marginBottom: '1rem',
          }}>
            <Shield size={14} style={{ marginRight: '0.35rem', verticalAlign: '-2px' }} />
            DNS SECURITY INTELLIGENCE
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
            fontSize: '1.1rem',
            color: '#8b949e',
            marginBottom: '1.5rem',
          }}>
            Producing <span style={{ color: '#d4a853' }}>Engineer's DNS Intelligence Reports</span> and{' '}
            <span style={{ color: '#d4a853' }}>Executive's DNS Intelligence Briefs</span> with{' '}
            <span style={{ color: '#d4a853' }}>posture&nbsp;scoring</span>
          </p>

          {/* Search Card */}
          <div style={{
            background: '#161b22',
            border: '1px solid #30363d',
            borderRadius: '0.75rem',
            padding: '1.5rem',
            maxWidth: '520px',
            margin: '0 auto',
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
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="text"
                placeholder="example.com or com"
                readOnly
                style={{
                  flex: 1,
                  padding: '0.6rem 0.75rem',
                  background: '#2b3035',
                  border: '1px solid #495057',
                  borderRadius: '0.375rem',
                  color: '#8b949e',
                  fontSize: '1rem',
                  outline: 'none',
                }}
              />
              <button style={{
                padding: '0.6rem 1.25rem',
                background: '#238636',
                border: 'none',
                borderRadius: '0.375rem',
                color: '#fff',
                fontSize: '1rem',
                fontWeight: 500,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                whiteSpace: 'nowrap',
              }}>
                <Search size={16} />
                Analyze
              </button>
            </div>
            <p style={{
              fontSize: '0.8rem',
              color: '#8b949e',
              marginTop: '0.75rem',
              lineHeight: 1.5,
            }}>
              Enter a domain (e.g., <strong style={{ color: '#c8956a' }}>example.com</strong>) or a top-level zone (e.g., <strong style={{ color: '#c8956a' }}>tech</strong>, <strong style={{ color: '#c8956a' }}>co.uk</strong>) — no https://. TLDs produce a <strong>Registry Zone Health Report</strong>.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
