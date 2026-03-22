export default function NonNormativePalette() {
  const basePath = import.meta.env.BASE_URL;
  const nnOwl = `${basePath}owl-NONNORMATIVE-transparent.png`;
  const crOwl = `${basePath}owl-CRITICAL-transparent.png`;

  const teals = [
    { name: "Black", hex: "#0d1117" },
    { name: "Dark Teal", hex: "#0f231e" },
    { name: "Deep Teal", hex: "#17302d" },
    { name: "Warm Teal", hex: "#1a3533" },
    { name: "Rich Teal", hex: "#1f3f3b" },
    { name: "Copper Mine", hex: "#224440" },
    { name: "Deep Sea", hex: "#264a45" },
    { name: "Verdigris", hex: "#2a504b" },
    { name: "Athena Teal", hex: "#2e5550" },
    { name: "Aegean", hex: "#36615b" },
  ];

  const reds = [
    { name: "Black", hex: "#0d1117" },
    { name: "Deep Oxblood", hex: "#2a0a10" },
    { name: "Oxblood", hex: "#3a1520" },
    { name: "Warm Oxblood", hex: "#4a1a1a" },
    { name: "Crimson Dark", hex: "#5a1a1a" },
  ];

  return (
    <div style={{ background: "#fff", padding: "24px", fontFamily: "Georgia, serif", color: "#222", minHeight: "100vh" }}>
      <h1 style={{ textAlign: "center", fontSize: "18px", color: "#1f3f3b", marginBottom: "4px" }}>
        NON-NORMATIVE — Background Palette
      </h1>
      <p style={{ textAlign: "center", fontSize: "11px", color: "#888", marginBottom: "20px" }}>
        Tilted green owl (truly transparent) with CSS background-color
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", justifyContent: "center", marginBottom: "32px" }}>
        {teals.map((t) => (
          <div key={t.hex} style={{ textAlign: "center", width: "100px" }}>
            <img
              src={nnOwl}
              alt={t.name}
              style={{
                width: "90px", height: "90px",
                borderRadius: "50%",
                backgroundColor: t.hex,
                border: "2px solid #C8A878",
                display: "block",
                margin: "0 auto",
              }}
            />
            <div style={{ fontSize: "9px", color: "#444", marginTop: "4px", fontWeight: "bold" }}>{t.name}</div>
            <div style={{ fontSize: "9px", color: "#888", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "16px", color: "#8b1a1a", marginBottom: "4px" }}>
        CRITICAL — Background Palette
      </h2>
      <p style={{ textAlign: "center", fontSize: "11px", color: "#888", marginBottom: "20px" }}>
        Reflected red owl (truly transparent) with CSS background-color
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", justifyContent: "center" }}>
        {reds.map((r) => (
          <div key={r.hex} style={{ textAlign: "center", width: "100px" }}>
            <img
              src={crOwl}
              alt={r.name}
              style={{
                width: "90px", height: "90px",
                borderRadius: "50%",
                backgroundColor: r.hex,
                border: "2px solid #C8A878",
                display: "block",
                margin: "0 auto",
              }}
            />
            <div style={{ fontSize: "9px", color: "#444", marginTop: "4px", fontWeight: "bold" }}>{r.name}</div>
            <div style={{ fontSize: "9px", color: "#888", fontFamily: "monospace" }}>{r.hex}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
