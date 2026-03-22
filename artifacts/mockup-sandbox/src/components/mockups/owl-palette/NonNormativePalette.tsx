export default function NonNormativePalette() {
  const b = import.meta.env.BASE_URL;
  const v = `?v=${Date.now()}`;

  const nonnorm = `${b}owl-NONNORMATIVE-complete-transparent.png${v}`;

  const seal = (bg: string, bc: string, sz = 120): React.CSSProperties => ({
    width: sz, height: sz,
    borderRadius: "50%",
    background: bg,
    border: `3px solid ${bc}`,
    padding: 3,
    display: "block",
    margin: "0 auto",
  });

  return (
    <div style={{ background: "#f5f0e8", padding: "32px 24px", fontFamily: "Georgia, serif", color: "#222", minHeight: "100vh" }}>
      <h1 style={{ textAlign: "center", fontSize: "18px", color: "#1a1a1a", marginBottom: "28px", letterSpacing: "0.06em", borderBottom: "2px solid #C8A878", paddingBottom: 12 }}>
        NON-NORMATIVE OWL — Transparent Asset on Backgrounds
      </h1>

      <div style={{ display: "flex", gap: 24, justifyContent: "center", flexWrap: "wrap", marginBottom: 40 }}>
        {[
          { label: "Black (current PDF)", hex: "#0d1117" },
          { label: "Dark Teal", hex: "#0f231e" },
          { label: "Deep Teal", hex: "#17302d" },
          { label: "Warm Teal", hex: "#1a3533" },
          { label: "Rich Teal", hex: "#1f3f3b" },
          { label: "Verdigris", hex: "#2a504b" },
          { label: "Aegean", hex: "#36615b" },
          { label: "White", hex: "#ffffff" },
        ].map((t) => (
          <div key={t.hex} style={{ textAlign: "center" }}>
            <img src={nonnorm} alt={t.label} style={seal(t.hex, "rgba(74,157,150,0.5)")} />
            <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 6, color: "#333" }}>{t.label}</div>
            <div style={{ fontSize: 8, color: "#999", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "13px", color: "#555", marginBottom: "12px", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        Flat on transparent (no circle bg)
      </h2>
      <div style={{ display: "flex", gap: 32, justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 150, height: 150, background: "repeating-conic-gradient(#ddd 0% 25%, #fff 0% 50%) 50% / 20px 20px", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <img src={nonnorm} alt="on checkerboard" style={{ width: 130, height: 130, display: "block" }} />
          </div>
          <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>Checkerboard (transparency proof)</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 150, height: 150, background: "#f5f0e8", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid #ddd" }}>
            <img src={nonnorm} alt="on cream" style={{ width: 130, height: 130, display: "block" }} />
          </div>
          <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>Cream paper (doc background)</div>
        </div>
      </div>
    </div>
  );
}
