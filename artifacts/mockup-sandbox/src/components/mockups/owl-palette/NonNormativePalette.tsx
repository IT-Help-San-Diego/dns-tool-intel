export default function NonNormativePalette() {
  const b = import.meta.env.BASE_URL;
  const v = `?v=${Date.now()}`;

  const owlFigure = `${b}owl-NONNORMATIVE-owlonly.png${v}`;
  const owlRing = `${b}owl-NONNORMATIVE-ring-transparent.png${v}`;
  const owlComplete = `${b}owl-NONNORMATIVE-complete-transparent.png${v}`;

  const checkerBg = "repeating-conic-gradient(#ccc 0% 25%, #fff 0% 50%) 50% / 16px 16px";

  const layeredSeal = (bg: string, size = 180) => (
    <div style={{ position: "relative", width: size, height: size }}>
      <div style={{
        position: "absolute", inset: 0,
        borderRadius: "50%",
        background: bg,
      }} />
      <img src={owlRing} alt="" style={{
        position: "absolute", inset: 0,
        width: "100%", height: "100%",
      }} />
      <img src={owlFigure} alt="NON-NORMATIVE owl" style={{
        position: "absolute",
        top: "12%", left: "12%",
        width: "76%", height: "76%",
      }} />
    </div>
  );

  return (
    <div style={{ background: "#f5f0e8", padding: "32px 24px", fontFamily: "Georgia, serif", color: "#222", minHeight: "100vh" }}>

      <h1 style={{ textAlign: "center", fontSize: "16px", color: "#1a1a1a", marginBottom: "6px", letterSpacing: "0.06em" }}>
        NON-NORMATIVE OWL — Layered Asset Kit
      </h1>
      <p style={{ textAlign: "center", fontSize: "10px", color: "#888", marginBottom: "28px" }}>
        Three independent layers: background plate · ring · owl figure
      </p>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Individual Layers (on checkerboard)
      </h2>
      <div style={{ display: "flex", gap: 32, justifyContent: "center", marginBottom: 36 }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 160, height: 160, background: checkerBg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ width: 140, height: 140, borderRadius: "50%", background: "#1f3f3b" }} />
          </div>
          <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8, color: "#333" }}>Layer 1: Background</div>
          <div style={{ fontSize: 8, color: "#999" }}>Circle plate #1f3f3b</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 160, height: 160, background: checkerBg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <img src={owlRing} alt="Ring layer" style={{ width: 140, height: 140 }} />
          </div>
          <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8, color: "#333" }}>Layer 2: Ring</div>
          <div style={{ fontSize: 8, color: "#999" }}>owl-NONNORMATIVE-ring-transparent.png</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ width: 160, height: 160, background: checkerBg, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <img src={owlFigure} alt="Owl figure layer" style={{ width: 110, height: 110 }} />
          </div>
          <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8, color: "#333" }}>Layer 3: Owl Figure</div>
          <div style={{ fontSize: 8, color: "#999" }}>owl-NONNORMATIVE-owlonly.png</div>
        </div>
      </div>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Composed — Layers Stacked
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
            <div style={{ fontSize: 9, fontWeight: "bold", marginTop: 8, color: "#333" }}>{t.label}</div>
            <div style={{ fontSize: 8, color: "#999", fontFamily: "monospace" }}>{t.hex}</div>
          </div>
        ))}
      </div>

      <h2 style={{ textAlign: "center", fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 16 }}>
        Flattened Asset — Transparency Proof
      </h2>
      <div style={{ display: "flex", gap: 32, justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ display: "inline-block", background: checkerBg, borderRadius: 8 }}>
            <img src={owlComplete} alt="Complete on checkerboard" style={{ width: 200, height: 200, display: "block" }} />
          </div>
          <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>Checkerboard</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ display: "inline-block", background: "#0d1117", borderRadius: 8 }}>
            <img src={owlComplete} alt="Complete on black" style={{ width: 200, height: 200, display: "block" }} />
          </div>
          <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>Black</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ display: "inline-block", background: "#1f3f3b", borderRadius: 8 }}>
            <img src={owlComplete} alt="Complete on teal" style={{ width: 200, height: 200, display: "block" }} />
          </div>
          <div style={{ fontSize: 9, color: "#555", marginTop: 6 }}>Rich Teal</div>
        </div>
      </div>
    </div>
  );
}
