export default function NonNormativePalette() {
  const basePath = import.meta.env.BASE_URL;
  const nnOwl = `${basePath}owl-NONNORMATIVE-clean-512.png`;
  const crOwl = `${basePath}owl-CRITICAL-clean-512.png`;
  const goldOwl = `${basePath}owl-of-athena.png`;

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
    <div style={{ background: "#111", padding: "24px", fontFamily: "Georgia, serif", color: "#ccc", minHeight: "100vh" }}>
      <h1 style={{ textAlign: "center", fontSize: "18px", color: "#C8A878", marginBottom: "4px" }}>
        NON-NORMATIVE — Background Palette
      </h1>
      <p style={{ textAlign: "center", fontSize: "11px", color: "#888", marginBottom: "20px" }}>
        Gold owl on teal · CSS background-color behind transparent PNG
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", justifyContent: "center", marginBottom: "32px" }}>
        {teals.map((t) => (
          <div key={t.hex} style={{ textAlign: "center", width: "100px" }}>
            <div style={{
              width: "90px", height: "90px", borderRadius: "50%",
              backgroundColor: t.hex, border: "2px solid #C8A878",
              overflow: "hidden", display: "flex", alignItems: "center", justifyContent: "center",
              margin: "0 auto"
            }}>
              <img src={nnOwl} alt={t.name} style={{ width: "90px", height: "90px" }} />
            </div>
            <div style={{ fontSize: "9px", color: "#aaa", marginTop: "4px", fontWeight: "bold" }}>{t.name}</div>
            <div style={{ fontSize: "9px", color: "#666", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "14px", color: "#C8A878", marginBottom: "4px" }}>
        Gold on Teal — Reference (#1f3f3b)
      </h2>
      <div style={{ display: "flex", gap: "24px", justifyContent: "center", marginBottom: "32px" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{
            width: "120px", height: "120px", borderRadius: "50%",
            backgroundColor: "#1f3f3b", border: "2px solid #C8A878",
            overflow: "hidden", margin: "0 auto"
          }}>
            <img src={goldOwl} alt="Gold on Teal" style={{ width: "120px", height: "120px" }} />
          </div>
          <div style={{ fontSize: "10px", color: "#C8A878", marginTop: "6px" }}>GOLD on Teal</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{
            width: "120px", height: "120px", borderRadius: "50%",
            backgroundColor: "#1f3f3b", border: "2px solid #C8A878",
            overflow: "hidden", margin: "0 auto"
          }}>
            <img src={nnOwl} alt="Green on Teal" style={{ width: "120px", height: "120px" }} />
          </div>
          <div style={{ fontSize: "10px", color: "#5fa89e", marginTop: "6px" }}>GREEN on Teal</div>
        </div>
      </div>

      <h1 style={{ textAlign: "center", fontSize: "18px", color: "#cc3333", marginBottom: "4px" }}>
        CRITICAL — Background Palette
      </h1>
      <p style={{ textAlign: "center", fontSize: "11px", color: "#888", marginBottom: "20px" }}>
        Red owl on oxblood · CSS background-color behind transparent PNG
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", justifyContent: "center" }}>
        {reds.map((r) => (
          <div key={r.hex} style={{ textAlign: "center", width: "100px" }}>
            <div style={{
              width: "90px", height: "90px", borderRadius: "50%",
              backgroundColor: r.hex, border: "2px solid #C8A878",
              overflow: "hidden", display: "flex", alignItems: "center", justifyContent: "center",
              margin: "0 auto"
            }}>
              <img src={crOwl} alt={r.name} style={{ width: "90px", height: "90px" }} />
            </div>
            <div style={{ fontSize: "9px", color: "#aaa", marginTop: "4px", fontWeight: "bold" }}>{r.name}</div>
            <div style={{ fontSize: "9px", color: "#666", fontFamily: "monospace" }}>{r.hex}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
