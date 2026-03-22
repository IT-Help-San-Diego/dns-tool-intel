export default function NonNormativePalette() {
  const b = import.meta.env.BASE_URL;
  const v = `?v=${Date.now()}`;

  const owlFigure = `${b}owl-NONNORMATIVE-owlonly.png${v}`;
  const owlRing = `${b}owl-NONNORMATIVE-ring-transparent.png${v}`;
  const owlComplete = `${b}owl-NONNORMATIVE-complete-transparent.png${v}`;

  const checkerBg = "repeating-conic-gradient(#ccc 0% 25%, #fff 0% 50%) 50% / 16px 16px";

  const layeredSeal = (bg: string, size = 180) => (
    <div style={{
      position: "relative",
      width: size, height: size,
      borderRadius: "50%",
      background: bg,
      overflow: "hidden",
      isolation: "isolate",
    }}>
      <img src={owlFigure} alt="NON-NORMATIVE owl" style={{
        position: "absolute",
        left: "50%", top: "50%",
        width: "72.27%", height: "72.27%",
        transform: "translate(-50%, -50%)",
        zIndex: 2,
        display: "block",
        pointerEvents: "none",
      }} />
      <img src={owlRing} alt="" style={{
        position: "absolute", inset: 0,
        width: "100%", height: "100%",
        zIndex: 3,
        display: "block",
        pointerEvents: "none",
      }} />
    </div>
  );

  return (
    <div style={{ background: "#f5f0e8", padding: "32px 24px", fontFamily: "Georgia, serif", color: "#222", minHeight: "100vh" }}>

      <h1 style={{ textAlign: "center", fontSize: "16px", color: "#1a1a1a", marginBottom: "6px", letterSpacing: "0.06em" }}>
        NON-NORMATIVE OWL — Layered Asset Kit
      </h1>
      <p style={{ textAlign: "center", fontSize: "10px", color: "#888", marginBottom: "28px" }}>
        L1 Background Plate (bottom) → L2 Owl Figure (middle) → L3 Ring Frame (top)
      </p>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Individual Layers
      </h2>
      <div style={{ display: "flex", gap: 32, justifyContent: "center", marginBottom: 36 }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 160, height: 160, background: checkerBg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ width: 140, height: 140, borderRadius: "50%", background: "#1f3f3b" }} />
          </div>
          <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8 }}>L1: Background Plate</div>
          <div style={{ fontSize: 8, color: "#999" }}>Opaque circle · bottom</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 160, height: 160, background: checkerBg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <img src={owlFigure} alt="Owl figure" style={{ width: 100, height: 100 }} />
          </div>
          <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8 }}>L2: Owl Figure</div>
          <div style={{ fontSize: 8, color: "#999" }}>z-index: 2 · middle</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 160, height: 160, background: checkerBg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <img src={owlRing} alt="Ring frame" style={{ width: 140, height: 140 }} />
          </div>
          <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8 }}>L3: Ring Frame</div>
          <div style={{ fontSize: 8, color: "#999" }}>z-index: 3 · top</div>
        </div>
      </div>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Composed — L1 + L2 + L3
      </h2>
      <div style={{ display: "flex", gap: 28, justifyContent: "center", flexWrap: "wrap", marginBottom: 36 }}>
        {[
          { label: "Black", hex: "#0d1117" },
          { label: "Deep Teal", hex: "#17302d" },
          { label: "Rich Teal", hex: "#1f3f3b" },
          { label: "Verdigris", hex: "#2a504b" },
          { label: "Aegean", hex: "#36615b" },
          { label: "White", hex: "#ffffff" },
        ].map((t) => (
          <div key={t.hex} style={{ textAlign: "center" }}>
            {layeredSeal(t.hex)}
            <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8 }}>{t.label}</div>
            <div style={{ fontSize: 8, color: "#999", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Flattened Composite — Transparency Proof
      </h2>
      <div style={{ display: "flex", gap: 32, justifyContent: "center" }}>
        {[
          { label: "Checkerboard", bg: checkerBg },
          { label: "Black", bg: "#0d1117" },
          { label: "Rich Teal", bg: "#1f3f3b" },
          { label: "White", bg: "#ffffff" },
        ].map((t) => (
          <div key={t.label} style={{ textAlign: "center" }}>
            <div style={{ display: "inline-block", background: t.bg, borderRadius: 8 }}>
              <img src={owlComplete} alt={t.label} style={{ width: 160, height: 160, display: "block" }} />
            </div>
            <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>{t.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
