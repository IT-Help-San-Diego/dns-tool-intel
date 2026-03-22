export default function NonNormativePalette() {
  const b = import.meta.env.BASE_URL;
  const v = `?v=${Date.now()}`;
  const nonnorm = `${b}owl-NONNORMATIVE-complete-transparent.png${v}`;

  const containerStyle = (bg: string, bc: string): React.CSSProperties => ({
    width: 160, height: 160,
    borderRadius: "50%",
    background: bg,
    border: `3px solid ${bc}`,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    overflow: "hidden",
  });

  const imgStyle: React.CSSProperties = {
    width: "100%",
    height: "100%",
    display: "block",
  };

  const checkerBg = "repeating-conic-gradient(#ccc 0% 25%, #fff 0% 50%) 50% / 16px 16px";

  return (
    <div style={{ background: "#f5f0e8", padding: "32px 24px", fontFamily: "Georgia, serif", color: "#222", minHeight: "100vh" }}>

      <h1 style={{ textAlign: "center", fontSize: "16px", color: "#1a1a1a", marginBottom: "8px", letterSpacing: "0.06em" }}>
        NON-NORMATIVE OWL — Transparent Asset Proof
      </h1>
      <p style={{ textAlign: "center", fontSize: "10px", color: "#888", marginBottom: "28px" }}>
        Background color is on the container — the image is untouched transparent PNG
      </p>

      <div style={{ textAlign: "center", marginBottom: 32 }}>
        <h2 style={{ fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 12 }}>
          Master — Native Size on Checkerboard
        </h2>
        <div style={{ display: "inline-block", background: checkerBg, padding: 0, borderRadius: 8 }}>
          <img src={nonnorm} alt="Transparent proof" style={{ width: 256, height: 256, display: "block" }} />
        </div>
      </div>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Background Swatch Tests
      </h2>
      <div style={{ display: "flex", gap: 20, justifyContent: "center", flexWrap: "wrap", marginBottom: 32 }}>
        {[
          { label: "Black", hex: "#0d1117", bc: "rgba(74,157,150,0.4)" },
          { label: "Deep Teal", hex: "#17302d", bc: "rgba(74,157,150,0.5)" },
          { label: "Rich Teal", hex: "#1f3f3b", bc: "rgba(74,157,150,0.6)" },
          { label: "Verdigris", hex: "#2a504b", bc: "rgba(74,157,150,0.5)" },
          { label: "White", hex: "#ffffff", bc: "rgba(50,120,110,0.4)" },
          { label: "Cream", hex: "#f5f0e8", bc: "rgba(50,120,110,0.3)" },
        ].map((t) => (
          <div key={t.hex} style={{ textAlign: "center" }}>
            <div style={containerStyle(t.hex, t.bc)}>
              <img src={nonnorm} alt={t.label} style={imgStyle} />
            </div>
            <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8, color: "#333" }}>{t.label}</div>
            <div style={{ fontSize: 8, color: "#999", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        No Circle — Flat on Backgrounds
      </h2>
      <div style={{ display: "flex", gap: 20, justifyContent: "center" }}>
        {[
          { label: "Checkerboard", bg: checkerBg },
          { label: "Black", bg: "#0d1117" },
          { label: "Rich Teal", bg: "#1f3f3b" },
          { label: "White", bg: "#ffffff" },
        ].map((t) => (
          <div key={t.label} style={{ textAlign: "center" }}>
            <div style={{ width: 140, height: 140, background: t.bg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <img src={nonnorm} alt={t.label} style={{ width: 120, height: 120, display: "block" }} />
            </div>
            <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>{t.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
