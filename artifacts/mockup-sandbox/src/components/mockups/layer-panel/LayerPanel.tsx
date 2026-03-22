import { useState } from "react";

const layers = [
  {
    id: "L0",
    name: "L0 — Background Plate",
    desc: "White background",
    type: "color" as const,
    color: "#FFFFFF",
  },
  {
    id: "L1",
    name: "L1 — Emerald Circle",
    desc: "r=252, #48B86E, LOCKED",
    type: "image" as const,
    src: "/__mockup/owl-assets/L1-emerald-540.png",
  },
  {
    id: "L4",
    name: "L4 — Outer Status Ring",
    desc: "r=248–262, #d4a853 gold",
    type: "image" as const,
    src: "/__mockup/owl-assets/L4-outer-ring-540.png",
  },
  {
    id: "L2",
    name: "L2 — Meander Ring",
    desc: "r=200–255, gold+teal, LOCKED",
    type: "image" as const,
    src: "/__mockup/owl-assets/L2-ring-540.png",
  },
  {
    id: "L3",
    name: "L3 — Owl Figure",
    desc: "r<184, LOCKED",
    type: "image" as const,
    src: "/__mockup/owl-assets/L3-owl-540.png",
  },
];

export function LayerPanel() {
  const [visible, setVisible] = useState<Record<string, boolean>>({
    L0: true,
    L1: true,
    L4: true,
    L2: true,
    L3: true,
  });

  const toggle = (id: string) => {
    setVisible((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "row",
        minHeight: "100vh",
        background: "#1a1a2e",
        fontFamily: "'Inter', system-ui, sans-serif",
        color: "#e0e0e0",
      }}
    >
      <div
        style={{
          width: 280,
          padding: "16px 12px",
          borderRight: "1px solid #333",
          background: "#12121f",
          flexShrink: 0,
        }}
      >
        <div
          style={{
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            color: "#888",
            marginBottom: 12,
            padding: "0 4px",
          }}
        >
          Layers — Bottom → Top
        </div>
        {layers.map((layer, i) => {
          const isOn = visible[layer.id];
          const locked = layer.desc.includes("LOCKED");
          return (
            <button
              key={layer.id}
              onClick={() => toggle(layer.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                width: "100%",
                padding: "10px 8px",
                marginBottom: 2,
                background: isOn ? "rgba(212,168,83,0.08)" : "transparent",
                border: "none",
                borderRadius: 6,
                cursor: "pointer",
                textAlign: "left",
                opacity: isOn ? 1 : 0.4,
                transition: "all 0.15s",
              }}
            >
              <div
                style={{
                  width: 18,
                  height: 18,
                  borderRadius: 3,
                  border: `2px solid ${isOn ? "#d4a853" : "#555"}`,
                  background: isOn ? "#d4a853" : "transparent",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 12,
                  color: "#12121f",
                  fontWeight: 700,
                  flexShrink: 0,
                }}
              >
                {isOn ? "✓" : ""}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    fontSize: 13,
                    fontWeight: 600,
                    color: isOn ? "#e0e0e0" : "#666",
                    whiteSpace: "nowrap",
                  }}
                >
                  {layer.name}
                  {locked && (
                    <span
                      style={{
                        fontSize: 10,
                        color: "#c0392b",
                        marginLeft: 6,
                        fontWeight: 700,
                      }}
                    >
                      🔒
                    </span>
                  )}
                </div>
                <div
                  style={{
                    fontSize: 10,
                    color: "#888",
                    marginTop: 2,
                  }}
                >
                  {layer.desc}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 24,
        }}
      >
        <div
          style={{
            position: "relative",
            width: 440,
            height: 440,
          }}
        >
          {visible.L0 && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                background: "#FFFFFF",
                borderRadius: "50%",
              }}
            />
          )}
          {layers
            .filter((l) => l.type === "image" && visible[l.id])
            .map((layer) => (
              <img
                key={layer.id}
                src={layer.type === "image" ? layer.src : ""}
                alt={layer.name}
                style={{
                  position: "absolute",
                  inset: 0,
                  width: "100%",
                  height: "100%",
                }}
              />
            ))}
          {!Object.values(visible).some(Boolean) && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#555",
                fontSize: 14,
              }}
            >
              All layers hidden
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
