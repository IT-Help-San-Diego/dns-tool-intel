export default function NonNormativePalette() {
  const b = import.meta.env.BASE_URL;

  const currentOwls = [
    { label: "NORMATIVE", src: `${b}owl-NORMATIVE-512.png`, border: "rgba(212,168,83,0.4)" },
    { label: "NON-NORMATIVE", src: `${b}owl-NONNORMATIVE-512.png`, border: "rgba(74,157,150,0.4)" },
    { label: "CRITICAL", src: `${b}owl-CRITICAL-512.png`, border: "rgba(139,0,0,0.4)" },
  ];

  const newOwl = `${b}owl-NONNORMATIVE-complete-transparent.png`;

  const tealBgs = [
    { label: "Black (current)", hex: "#0d1117" },
    { label: "Deep Teal", hex: "#17302d" },
    { label: "Rich Teal", hex: "#1f3f3b" },
    { label: "Verdigris", hex: "#2a504b" },
    { label: "Aegean", hex: "#36615b" },
    { label: "White", hex: "#ffffff" },
  ];

  const sealStyle = (bg: string, borderColor: string): React.CSSProperties => ({
    width: 100, height: 100,
    borderRadius: "50%",
    background: bg,
    border: `2px solid ${borderColor}`,
    padding: 2,
    display: "block",
    margin: "0 auto",
  });

  return (
    <div style={{ background: "#1a1a2e", padding: "24px 16px", fontFamily: "Georgia, serif", color: "#ccc", minHeight: "100vh" }}>
      <h1 style={{ textAlign: "center", fontSize: "16px", color: "#C8A878", marginBottom: "16px" }}>
        Side by Side — Current vs New Transparent
      </h1>

      <h2 style={{ textAlign: "center", fontSize: "12px", color: "#888", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.1em" }}>
        Current (as they appear in PDFs now)
      </h2>
      <div style={{ display: "flex", gap: 24, justifyContent: "center", marginBottom: 32 }}>
        {currentOwls.map((o) => (
          <div key={o.label} style={{ textAlign: "center" }}>
            <img src={o.src} alt={o.label} style={sealStyle("#0d1117", o.border)} />
            <div style={{ fontSize: 9, color: "#aaa", marginTop: 6 }}>{o.label}</div>
            <div style={{ fontSize: 8, color: "#666", fontFamily: "monospace" }}>bg: #0d1117</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "12px", color: "#5fa89e", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.1em" }}>
        New NON-NORMATIVE transparent — on different backgrounds
      </h2>
      <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap", marginBottom: 32 }}>
        {tealBgs.map((t) => (
          <div key={t.hex} style={{ textAlign: "center" }}>
            <img src={newOwl} alt={`on ${t.label}`} style={sealStyle(t.hex, "rgba(74,157,150,0.4)")} />
            <div style={{ fontSize: 9, color: "#aaa", marginTop: 6 }}>{t.label}</div>
            <div style={{ fontSize: 8, color: "#666", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "12px", color: "#C8A878", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.1em" }}>
        All three as they would appear in PDF headers
      </h2>
      <div style={{ display: "flex", gap: 24, justifyContent: "center", background: "#fff", padding: "20px 32px", borderRadius: 8 }}>
        <div style={{ textAlign: "center" }}>
          <img src={`${b}owl-NORMATIVE-512.png`} alt="NORMATIVE" style={sealStyle("#0d1117", "rgba(212,168,83,0.6)")} />
          <div style={{ fontSize: 9, color: "#333", marginTop: 6, fontWeight: "bold" }}>NORMATIVE</div>
          <div style={{ fontSize: 8, color: "#888" }}>bg: #0d1117 (black)</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <img src={newOwl} alt="NON-NORMATIVE" style={sealStyle("#1f3f3b", "rgba(74,157,150,0.6)")} />
          <div style={{ fontSize: 9, color: "#333", marginTop: 6, fontWeight: "bold" }}>NON-NORMATIVE</div>
          <div style={{ fontSize: 8, color: "#888" }}>bg: #1f3f3b (teal)</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <img src={`${b}owl-CRITICAL-512.png`} alt="CRITICAL" style={sealStyle("#0d1117", "rgba(139,0,0,0.6)")} />
          <div style={{ fontSize: 9, color: "#333", marginTop: 6, fontWeight: "bold" }}>CRITICAL</div>
          <div style={{ fontSize: 8, color: "#888" }}>bg: #0d1117 (black)</div>
        </div>
      </div>
    </div>
  );
}
