export default function NonNormativePalette() {
  const b = import.meta.env.BASE_URL;

  const norm = `${b}owl-NORMATIVE-complete-transparent.png`;
  const nonnorm = `${b}owl-NONNORMATIVE-complete-transparent.png`;
  const crit = `${b}owl-CRITICAL-complete-transparent.png`;

  const sealStyle = (bg: string, borderColor: string): React.CSSProperties => ({
    width: 110, height: 110,
    borderRadius: "50%",
    background: bg,
    border: `2px solid ${borderColor}`,
    padding: 2,
    display: "block",
    margin: "0 auto",
  });

  return (
    <div style={{ background: "#fff", padding: "28px 20px", fontFamily: "Georgia, serif", color: "#222", minHeight: "100vh" }}>
      <h1 style={{ textAlign: "center", fontSize: "16px", color: "#333", marginBottom: "20px", letterSpacing: "0.05em" }}>
        OWL SEMAPHORE — PDF Header Treatment
      </h1>

      <div style={{ display: "flex", gap: 40, justifyContent: "center", marginBottom: 40 }}>
        <div style={{ textAlign: "center" }}>
          <img src={norm} alt="NORMATIVE" style={sealStyle("#0d1117", "rgba(212,168,83,0.6)")} />
          <div style={{ fontSize: 10, fontWeight: "bold", marginTop: 8, color: "#333" }}>NORMATIVE</div>
          <div style={{ fontSize: 8, color: "#888", fontFamily: "monospace" }}>bg: #0d1117 (black)</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <img src={nonnorm} alt="NON-NORMATIVE" style={sealStyle("#1f3f3b", "rgba(74,157,150,0.6)")} />
          <div style={{ fontSize: 10, fontWeight: "bold", marginTop: 8, color: "#333" }}>NON-NORMATIVE</div>
          <div style={{ fontSize: 8, color: "#888", fontFamily: "monospace" }}>bg: #1f3f3b (teal)</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <img src={crit} alt="CRITICAL" style={sealStyle("#3a1520", "rgba(139,0,0,0.6)")} />
          <div style={{ fontSize: 10, fontWeight: "bold", marginTop: 8, color: "#333" }}>CRITICAL</div>
          <div style={{ fontSize: 8, color: "#888", fontFamily: "monospace" }}>bg: #3a1520 (oxblood)</div>
        </div>
      </div>

      <h2 style={{ textAlign: "center", fontSize: "12px", color: "#555", marginBottom: "12px", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        NON-NORMATIVE — Teal Background Options
      </h2>
      <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap", marginBottom: 32 }}>
        {[
          { label: "Black", hex: "#0d1117" },
          { label: "Dark Teal", hex: "#0f231e" },
          { label: "Deep Teal", hex: "#17302d" },
          { label: "Warm Teal", hex: "#1a3533" },
          { label: "Rich Teal", hex: "#1f3f3b" },
          { label: "Verdigris", hex: "#2a504b" },
          { label: "Aegean", hex: "#36615b" },
        ].map((t) => (
          <div key={t.hex} style={{ textAlign: "center" }}>
            <img src={nonnorm} alt={t.label} style={sealStyle(t.hex, "rgba(74,157,150,0.5)")} />
            <div style={{ fontSize: 8, color: "#555", marginTop: 4, fontWeight: "bold" }}>{t.label}</div>
            <div style={{ fontSize: 8, color: "#999", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "12px", color: "#555", marginBottom: "12px", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        CRITICAL — Oxblood Background Options
      </h2>
      <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
        {[
          { label: "Black", hex: "#0d1117" },
          { label: "Deep Oxblood", hex: "#2a0a10" },
          { label: "Oxblood", hex: "#3a1520" },
          { label: "Warm Oxblood", hex: "#4a1a1a" },
          { label: "Crimson Dark", hex: "#5a1a1a" },
        ].map((r) => (
          <div key={r.hex} style={{ textAlign: "center" }}>
            <img src={crit} alt={r.label} style={sealStyle(r.hex, "rgba(139,0,0,0.5)")} />
            <div style={{ fontSize: 8, color: "#555", marginTop: 4, fontWeight: "bold" }}>{r.label}</div>
            <div style={{ fontSize: 8, color: "#999", fontFamily: "monospace" }}>{r.hex}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
